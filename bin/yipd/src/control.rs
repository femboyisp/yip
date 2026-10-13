//! UNIX domain control socket implementation for headless yipd management (#124).
//!
//! Provides a non-blocking UNIX domain socket server speaking newline-delimited JSON
//! for querying daemon status, listing peer telemetry, and dynamically adding/removing peers.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use crate::config::PeerConfig;
use crate::peer_manager::{PeerManager, PeerStats};

/// Inbound control commands received over the UNIX socket.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "cmd")]
pub enum ControlCmd {
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "list_peers")]
    ListPeers,
    #[serde(rename = "add_peer")]
    AddPeer {
        public_key: String,
        endpoint: Option<String>,
    },
    #[serde(rename = "remove_peer")]
    RemovePeer { public_key: String },
}

/// Outbound control command responses returned to clients.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ControlResponse {
    Status {
        ok: bool,
        version: String,
        node_addr: String,
        device: String,
        peers_count: usize,
        uptime_secs: u64,
    },
    ListPeers {
        ok: bool,
        peers: Vec<PeerStats>,
    },
    Ack {
        ok: bool,
        message: String,
    },
    Err {
        ok: bool,
        error: String,
    },
}

/// A request dispatched from a socket client to the main dataplane thread.
pub struct ControlRequest {
    pub cmd: ControlCmd,
    pub responder: Sender<ControlResponse>,
}

/// Controller handle maintained by the dataplane / tunnel event loop.
pub struct ControlHandle {
    rx: Receiver<ControlRequest>,
    _worker: JoinHandle<()>,
    socket_path: PathBuf,
}

impl ControlHandle {
    /// Bind a new UNIX domain socket listener at `path` and spawn the background listener thread.
    pub fn bind(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(false)?;

        let (tx, rx) = channel();
        let socket_path = path.clone();

        let worker = thread::Builder::new()
            .name("yipd-control".into())
            .spawn(move || {
                run_listener(listener, tx);
            })?;

        Ok(Self {
            rx,
            _worker: worker,
            socket_path,
        })
    }

    /// Try to receive the next pending control request without blocking.
    pub fn try_recv(&self) -> Result<ControlRequest, TryRecvError> {
        self.rx.try_recv()
    }

    /// Drain and execute all pending control requests against the provided `PeerManager`.
    pub fn drain_and_dispatch(&self, pm: &mut PeerManager, device_name: &str, start_time: Instant) {
        while let Ok(req) = self.try_recv() {
            let resp = dispatch_cmd(pm, req.cmd, device_name, start_time);
            let _ = req.responder.send(resp);
        }
    }
}

impl Drop for ControlHandle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Background thread loop accepting connections and servicing client requests.
fn run_listener(listener: UnixListener, req_tx: Sender<ControlRequest>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            break;
        };
        let tx = req_tx.clone();
        thread::spawn(move || {
            handle_client(stream, tx);
        });
    }
}

/// Read newline-delimited JSON commands from a client connection and write responses.
fn handle_client(stream: UnixStream, req_tx: Sender<ControlRequest>) {
    let Ok(mut reader) = stream.try_clone().map(BufReader::new) else {
        return;
    };
    let mut writer = stream;
    let mut line = String::new();

    while let Ok(n) = reader.read_line(&mut line) {
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let parsed: Result<ControlCmd, _> = serde_json::from_str(trimmed);
        match parsed {
            Ok(cmd) => {
                let (resp_tx, resp_rx) = channel();
                let req = ControlRequest {
                    cmd,
                    responder: resp_tx,
                };
                if req_tx.send(req).is_err() {
                    let err_resp = ControlResponse::Err {
                        ok: false,
                        error: "server shutting down".into(),
                    };
                    let _ = send_response(&mut writer, &err_resp);
                    break;
                }
                match resp_rx.recv() {
                    Ok(resp) => {
                        if send_response(&mut writer, &resp).is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        let err_resp = ControlResponse::Err {
                            ok: false,
                            error: "request dropped by event loop".into(),
                        };
                        let _ = send_response(&mut writer, &err_resp);
                        break;
                    }
                }
            }
            Err(e) => {
                let err_resp = ControlResponse::Err {
                    ok: false,
                    error: format!("invalid JSON command: {e}"),
                };
                if send_response(&mut writer, &err_resp).is_err() {
                    break;
                }
            }
        }
        line.clear();
    }
}

fn send_response(writer: &mut UnixStream, resp: &ControlResponse) -> std::io::Result<()> {
    let mut json = serde_json::to_string(resp).map_err(|e| std::io::Error::other(e.to_string()))?;
    json.push('\n');
    writer.write_all(json.as_bytes())?;
    writer.flush()
}

/// Synchronously process a command against `PeerManager`.
pub fn dispatch_cmd(
    pm: &mut PeerManager,
    cmd: ControlCmd,
    device_name: &str,
    start_time: Instant,
) -> ControlResponse {
    match cmd {
        ControlCmd::Status => {
            let stats = pm.peer_stats();
            ControlResponse::Status {
                ok: true,
                version: env!("CARGO_PKG_VERSION").into(),
                node_addr: pm.local_addr().to_string(),
                device: device_name.into(),
                peers_count: stats.len(),
                uptime_secs: start_time.elapsed().as_secs(),
            }
        }
        ControlCmd::ListPeers => {
            let peers = pm.peer_stats();
            ControlResponse::ListPeers { ok: true, peers }
        }
        ControlCmd::AddPeer {
            public_key,
            endpoint,
        } => {
            let pk = match crate::config::hex_to_32(&public_key) {
                Ok(k) => k,
                Err(_) => {
                    return ControlResponse::Err {
                        ok: false,
                        error: "invalid public_key hex (must be 64 hex characters)".into(),
                    };
                }
            };
            let ep: Option<SocketAddr> = match endpoint {
                Some(s) => match s.parse() {
                    Ok(a) => Some(a),
                    Err(_) => {
                        return ControlResponse::Err {
                            ok: false,
                            error: "invalid endpoint socket address".into(),
                        };
                    }
                },
                None => None,
            };
            match pm.add_peer(PeerConfig {
                public_key: pk,
                endpoint: ep,
            }) {
                Ok(()) => ControlResponse::Ack {
                    ok: true,
                    message: "peer added".into(),
                },
                Err(e) => ControlResponse::Err {
                    ok: false,
                    error: e.into(),
                },
            }
        }
        ControlCmd::RemovePeer { public_key } => {
            let pk = match crate::config::hex_to_32(&public_key) {
                Ok(k) => k,
                Err(_) => {
                    return ControlResponse::Err {
                        ok: false,
                        error: "invalid public_key hex (must be 64 hex characters)".into(),
                    };
                }
            };
            match pm.remove_peer(&pk) {
                Ok(()) => ControlResponse::Ack {
                    ok: true,
                    message: "peer removed".into(),
                },
                Err(e) => ControlResponse::Err {
                    ok: false,
                    error: e.into(),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_protocol_status_serialization() {
        let mut pm = crate::peer_manager::testutil::test_peer_manager();
        let start = Instant::now();
        let resp = dispatch_cmd(&mut pm, ControlCmd::Status, "yip0", start);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"device\":\"yip0\""));
        assert!(json.contains("\"peers_count\":1"));
    }

    #[test]
    fn control_protocol_add_and_list_peers() {
        let mut pm = crate::peer_manager::testutil::test_peer_manager();
        let start = Instant::now();

        let new_pk_hex = "02".repeat(32);
        let add_cmd = ControlCmd::AddPeer {
            public_key: new_pk_hex.clone(),
            endpoint: Some("198.51.100.2:51820".into()),
        };
        let resp = dispatch_cmd(&mut pm, add_cmd, "yip0", start);
        assert_eq!(
            resp,
            ControlResponse::Ack {
                ok: true,
                message: "peer added".into()
            }
        );

        let list_cmd = ControlCmd::ListPeers;
        let resp = dispatch_cmd(&mut pm, list_cmd, "yip0", start);
        if let ControlResponse::ListPeers { ok, peers } = resp {
            assert!(ok);
            assert_eq!(peers.len(), 2);
            assert_eq!(peers[1].public_key, [2u8; 32]);
        } else {
            panic!("expected ListPeers response");
        }

        let remove_cmd = ControlCmd::RemovePeer {
            public_key: new_pk_hex,
        };
        let resp = dispatch_cmd(&mut pm, remove_cmd, "yip0", start);
        assert_eq!(
            resp,
            ControlResponse::Ack {
                ok: true,
                message: "peer removed".into()
            }
        );
        assert_eq!(pm.peer_stats().len(), 1);
    }

    #[test]
    fn control_handle_socket_round_trip() {
        let socket_path = format!("/tmp/test_control_{}.sock", std::process::id());
        let handle = ControlHandle::bind(&socket_path).unwrap();

        let mut pm = crate::peer_manager::testutil::test_peer_manager();
        let start = Instant::now();

        let client = UnixStream::connect(&socket_path).unwrap();
        let mut writer = client.try_clone().unwrap();
        let mut reader = BufReader::new(client);

        // Send status request
        writer.write_all(b"{\"cmd\":\"status\"}\n").unwrap();
        writer.flush().unwrap();

        // Wait for request in main thread
        let mut req = None;
        for _ in 0..50 {
            if let Ok(r) = handle.try_recv() {
                req = Some(r);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let req = req.expect("request should arrive at handle within 500ms");
        let resp = dispatch_cmd(&mut pm, req.cmd, "yip0", start);
        req.responder.send(resp).unwrap();

        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("\"device\":\"yip0\""));
    }
}
