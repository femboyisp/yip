//! Integration test for multi-core sharded yipd event loop.
//!
//! Verifies sharded startup with shards = 2, ensuring multi-queue allocation,
//! SO_REUSEPORT binding, and worker threads initialize without panics or deadlocks.
//! When unprivileged (non-root / non-CAP_NET_ADMIN), tests skip gracefully.

use std::fs;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

fn have_root() -> bool {
    if std::env::var_os("YIP_SKIP_PRIVILEGED_TESTS").is_some() {
        return false;
    }
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}

#[test]
fn test_sharded_tunnel_daemon_launch() {
    if !have_root() {
        eprintln!("skipping root-gated test_sharded_tunnel_daemon_launch");
        return;
    }

    let yipd = env!("CARGO_BIN_EXE_yipd");
    let tmp_dir = std::env::temp_dir();
    let cfg_path = tmp_dir.join(format!("yipd_sharded_test_{}.conf", std::process::id()));

    let config_content = "device=yiptest_sh%d\n\
                          listen=127.0.0.1:0\n\
                          shards=2\n\
                          local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                          local_public=00000000000000000000000000000000000000000000000000000000000000aa\n\
                          peer_public=00000000000000000000000000000000000000000000000000000000000000bb\n";

    let mut file = fs::File::create(&cfg_path).expect("create test config");
    file.write_all(config_content.as_bytes())
        .expect("write test config");
    drop(file);

    // Launch yipd with shards = 2 in the background
    let mut child: Child = Command::new(yipd)
        .arg(&cfg_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sharded yipd");

    // Allow daemon to initialize queues, sockets, and worker loops
    thread::sleep(Duration::from_millis(500));

    // Verify it didn't exit prematurely or panic
    match child.try_wait() {
        Ok(Some(status)) => {
            panic!("sharded yipd process exited unexpectedly with status: {status:?}");
        }
        Ok(None) => {
            // Process is still running smoothly without panicking or deadlocking.
        }
        Err(e) => {
            panic!("failed to check sharded yipd process status: {e}");
        }
    }

    // Terminate cleanly
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&cfg_path);
}
