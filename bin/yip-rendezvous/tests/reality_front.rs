//! REALITY front end-to-end integration test (REALITY.1 Task 5).
//!
//! `bin/yip-rendezvous` has no `[lib]` target (see its `Cargo.toml`: only a
//! `[[bin]]`), so an integration test living in `tests/` cannot `use` the
//! `tls_front`/`reality` modules directly — those are private to `main.rs`'s
//! module tree and simply unreachable from an external test crate, no matter
//! how `pub` their items are declared. `tests/smoke.rs` already establishes
//! the pattern this crate uses for integration coverage: spawn the compiled
//! binary (`CARGO_BIN_EXE_yip-rendezvous`) and drive it over real sockets.
//! This test follows that pattern — no visibility widening was needed or
//! made.
//!
//! What it proves: the headline REALITY.1 property, exercised through the
//! actual CLI/process boundary (not just the in-process unit tests in
//! `src/reality.rs` / `src/tls_front.rs`) — a connection to the REALITY front
//! that never authenticates is transparently spliced to `--reality-dest`'s
//! real upstream, with whatever bytes it already sent replayed first.
use std::net::{TcpListener as StdTcpListener, UdpSocket};
use std::process::{Child, Command};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Kills and reaps the wrapped `yip-rendezvous` child on drop, so a
/// panicking assertion never leaks a process across test runs (this test is
/// meant to be run repeatedly to check for flakes).
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A currently-free loopback UDP port (bind ephemeral, read back the
/// kernel-assigned port, then drop) — mirrors `smoke.rs`'s `free_udp_port`.
/// `yip-rendezvous` requires a UDP listen address positionally even though
/// this test never sends it any UDP traffic.
fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral udp")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// A currently-free loopback TCP port, same TOCTOU-tolerant technique as
/// `free_udp_port` above (fine on loopback in a test).
fn free_tcp_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral tcp")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// Hex-encode `bytes` (lowercase), for the `--reality-private-key`/
/// `--obf-psk` CLI arguments (which take 64-char hex for 32 bytes).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A cheap, monotonically-distinct suffix for the per-test temp dir name —
/// avoids collisions across the repeated runs used to check this test isn't
/// flaky (PID alone can repeat across separate fast `cargo test` process
/// launches).
fn unique_suffix() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    u64::try_from(nanos).unwrap_or(0)
}

/// Poll `addr` with real TCP connects (bounded by an overall timeout) until
/// one succeeds — proves the front is actually bound and accepting, rather
/// than racing a fixed sleep against a slow-starting child process.
async fn wait_until_tcp_listening(addr: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("yip-rendezvous TLS front never started listening");
}

/// Splice-to-dest E2E (REALITY.1 headline property): a connection to the
/// REALITY front that sends a TLS-record-framed but unparseable-as-ClientHello
/// (hence necessarily un-authed) first message must be transparently spliced
/// to `--reality-dest`'s real upstream — proven by reading the *upstream's*
/// banner back through the front.
#[tokio::test]
async fn unauthenticated_connection_is_spliced_to_dest() {
    // "dest": a bare TCP server that answers any connection with a fixed
    // banner, standing in for the real upstream site REALITY splices to.
    let dest_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind dest listener");
    let dest_addr = dest_listener.local_addr().expect("dest local_addr");
    tokio::spawn(async move {
        let Ok((mut stream, _)) = dest_listener.accept().await else {
            return;
        };
        // Best-effort drain of whatever the front replayed, so the socket's
        // receive buffer is empty before we close — avoids a RST-on-close
        // racing the banner write below.
        let mut sink = [0u8; 256];
        let _ = tokio::time::timeout(Duration::from_millis(200), stream.read(&mut sink)).await;
        let _ = stream.write_all(b"HELLO-FROM-DEST").await;
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
    });

    // A throwaway self-signed cert for the front's real BoringSSL acceptor.
    // Never actually reached by the connection under test (it never
    // authenticates), but `--listen-tcp` requires `--tls-cert`/`--tls-key`.
    let dir = std::env::temp_dir().join(format!(
        "yip-rdv-reality-e2e-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::create_dir_all(&dir).expect("mkdir temp dir");
    let cert = rcgen::generate_simple_self_signed(vec!["relay.test".into()])
        .expect("generate self-signed cert");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert.pem");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key.pem");

    let udp_addr = format!("127.0.0.1:{}", free_udp_port());
    let tcp_addr = format!("127.0.0.1:{}", free_tcp_port());
    let obf_psk = hex(&[0x11u8; 32]);
    let reality_priv_hex = hex(&[7u8; 32]); // matches the task brief's RealityCfg { priv_key: [7u8; 32], .. }

    let child = Command::new(env!("CARGO_BIN_EXE_yip-rendezvous"))
        .arg(&udp_addr)
        .arg("--obf-psk")
        .arg(&obf_psk)
        .arg("--listen-tcp")
        .arg(&tcp_addr)
        .arg("--tls-cert")
        .arg(cert_path.to_str().expect("cert path is utf-8"))
        .arg("--tls-key")
        .arg(key_path.to_str().expect("key path is utf-8"))
        .arg("--reality-dest")
        .arg(dest_addr.to_string())
        .arg("--reality-private-key")
        .arg(&reality_priv_hex)
        // No --reality-short-id: an empty short_ids list can never accept
        // ANY client, guaranteeing this connection is un-authed regardless
        // of exactly what (garbage) bytes it sends.
        .spawn()
        .expect("spawn yip-rendezvous");
    let _guard = KillOnDrop(child);

    wait_until_tcp_listening(&tcp_addr).await;

    // A TLS-record-framed but unparseable-as-ClientHello first message
    // (handshake_type byte 0xAA is not client_hello/0x01): the front's parse
    // fails, `authed` folds to `false` via the same code path as a
    // well-formed-but-unauthed hello, and it must splice to dest.
    let body = vec![0xAAu8; 20];
    let mut record = vec![0x16u8, 0x03, 0x01];
    record.extend_from_slice(
        &u16::try_from(body.len())
            .expect("test body fits in u16")
            .to_be_bytes(),
    );
    record.extend_from_slice(&body);

    let mut client = TcpStream::connect(&tcp_addr)
        .await
        .expect("connect to REALITY front");
    client
        .write_all(&record)
        .await
        .expect("write fake ClientHello record");

    let mut got = Vec::new();
    let read_result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut chunk = [0u8; 256];
        loop {
            let n = client.read(&mut chunk).await.expect("read from front");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
            if String::from_utf8_lossy(&got).contains("HELLO-FROM-DEST") {
                break;
            }
        }
    })
    .await;
    assert!(
        read_result.is_ok(),
        "timed out waiting for dest's banner to be spliced back to the client; got {got:?}"
    );
    assert!(
        String::from_utf8_lossy(&got).contains("HELLO-FROM-DEST"),
        "expected the spliced dest banner in the client's read bytes, got {got:?}"
    );
}
