//! REALITY.2 Task 8: the live proof. Everything up to here (Tasks 1–7) has
//! only ever been exercised in-process, against `tokio::io::duplex` or a mock
//! peer. This test drives the *entire* hand-rolled TLS 1.3 client — Chrome-
//! faithful `ClientHello` → parsed `ServerHello` → RFC 8446 key schedule →
//! decrypted server handshake flight → sent client `Finished` →
//! application-data stream — against real internet infrastructure and reads
//! back a genuine HTTP response. REALITY's auth seal cannot validate against
//! a non-REALITY-aware real site (that requires our own `yipd` on the other
//! end), but the zero-cert-auth TLS 1.3 handshake itself must still complete
//! byte-for-byte per RFC 8446, because a real server only ever sees "a
//! ClientHello it knows how to answer" — it has no idea a REALITY seal is
//! riding inside `legacy_session_id`.
//!
//! `#[ignore]`d so the default (offline) CI run stays hermetic; run with
//! `cargo test -p yip-utls -- --ignored`.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Whether `buf` is a plausible start of a real HTTP response, either
/// HTTP/1.1 text or a syntactically valid HTTP/2 frame header (9-byte
/// `length(3) | type(1) | flags(1) | R+stream_id(4)`, RFC 9113 §4.1).
///
/// Both are legitimate: this crate's crafted `ClientHello`'s `alpn`
/// extension is byte-faithful to real Chrome-150 (`h2` listed before
/// `http/1.1` — the very first two characters of the locked JA4 hash,
/// `t13d1516h2_...`, ARE that ALPN preference), so a real ALPN-aware server
/// that supports HTTP/2 (Cloudflare, Google) negotiates `h2` and answers a
/// raw `GET / HTTP/1.1` text request with real, correctly-decrypted HTTP/2
/// binary framing instead of a text status line — proof the TLS 1.3 layer
/// worked perfectly, just not something a text HTTP/1.1 parser understands.
/// A server without HTTP/2 (`www.microsoft.com` here) negotiates `http/1.1`
/// and answers with a normal text status line.
fn looks_like_real_http_response(buf: &[u8]) -> Option<&'static str> {
    if buf.starts_with(b"HTTP/1.1 ") || buf.starts_with(b"HTTP/1.0 ") {
        return Some("HTTP/1.x status line");
    }
    // HTTP/2 frame header: 3-byte length, 1-byte type, 1-byte flags, 4-byte
    // (reserved-bit + stream id). Known frame types are 0x00..=0x09 (RFC
    // 9113 §6); the server's first frame here is virtually always its
    // preface SETTINGS (0x04) on stream 0.
    if buf.len() >= 9 {
        let frame_type = buf[3];
        let stream_id = u32::from_be_bytes([buf[4] & 0x7f, buf[5], buf[6], buf[7]]);
        if frame_type <= 0x09 && stream_id == 0 {
            return Some("HTTP/2 frame header (ALPN negotiated h2)");
        }
    }
    None
}

/// Connects to `host:443`, completes the REALITY/TLS 1.3 handshake, sends a
/// plaintext HTTP/1.1 GET, and returns everything read back before the peer
/// closes (or a generous cap), so the caller can assert on the status line.
async fn handshake_and_get(host: &str) -> Result<Vec<u8>, String> {
    let tcp = tokio::net::TcpStream::connect((host, 443))
        .await
        .map_err(|e| format!("tcp connect to {host}:443 failed: {e}"))?;
    tcp.set_nodelay(true).ok();

    // A random/zero REALITY pub + short_id: the auth seal won't validate at
    // a real site (there's no REALITY-aware proxy on the other end to open
    // it), but that's fine — REALITY's seal rides inside a field
    // (`legacy_session_id`) a normal TLS 1.3 server never inspects, so the
    // handshake proceeds exactly as it would for any other client.
    let mut s = yip_utls::connect(tcp, host, &[0u8; 32], [0u8; 8], false)
        .await
        .map_err(|e| format!("tls handshake with {host} failed: {e}"))?;

    let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write GET to {host} failed: {e}"))?;
    s.flush()
        .await
        .map_err(|e| format!("flush GET to {host} failed: {e}"))?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    // Read until we recognize a real HTTP/1.x or HTTP/2 response (see
    // `looks_like_real_http_response`), the peer closes, or we hit a sane
    // cap (real front pages can be large and an h2 connection has no
    // "\r\n\r\n" end-of-headers marker to wait for; we only need enough
    // bytes to prove the decrypt is real).
    loop {
        if buf.len() >= 16 * 1024 {
            break;
        }
        let n = match s.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(format!("read response from {host} failed: {e}")),
        };
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || looks_like_real_http_response(&buf).is_some()
        {
            break;
        }
    }
    Ok(buf)
}

/// The real proof: a full RFC 8446 one-round-trip TLS 1.3 handshake — our
/// Chrome-150 `ClientHello`, the real site's `ServerHello`, the RFC 8446 key
/// schedule, decryption of the server's encrypted handshake flight, our
/// sealed client `Finished`, and the resulting application-data stream — all
/// the way to a parsed HTTP status line from real internet infrastructure.
///
/// Tries a small list of large, TLS-1.3-serving sites in order, since any
/// single site's edge can reset a connection for reasons unrelated to this
/// client's correctness (rate limiting, geo routing, transient network
/// flakiness). The test only fails if *every* candidate fails.
#[tokio::test]
#[ignore] // network; run with `cargo test -p yip-utls -- --ignored`
async fn handshake_and_http_get_cloudflare() {
    let candidates = ["cloudflare.com", "google.com", "www.microsoft.com"];
    let mut failures = Vec::new();

    for host in candidates {
        match handshake_and_get(host).await {
            Ok(buf) => {
                let head = String::from_utf8_lossy(&buf[..buf.len().min(200)]).to_string();
                let kind = looks_like_real_http_response(&buf).unwrap_or_else(|| {
                    panic!("expected a real HTTP/1.x or HTTP/2 response from {host}, got: {head:?}")
                });
                eprintln!("[handshake_live] {host} ({kind}): {head:?}");
                return; // one real end-to-end success is the proof.
            }
            Err(e) => {
                eprintln!("[handshake_live] {host} failed: {e}");
                failures.push(format!("{host}: {e}"));
            }
        }
    }

    panic!(
        "live TLS 1.3 handshake + HTTP GET failed against every candidate site:\n{}",
        failures.join("\n")
    );
}

/// Local, controlled fallback per the Task 8 brief: drives the same
/// `connect` orchestration against a `openssl s_server -tls1_3` endpoint on
/// 127.0.0.1 (started by the developer/CI harness OUT OF BAND — this test
/// does not spawn it itself), to isolate "a real-but-strict CDN edge
/// rejected our hello" from "the hello is generically malformed against any
/// RFC 8446 server". Not run by default; only used ad hoc while debugging.
#[tokio::test]
#[ignore]
async fn handshake_against_local_openssl_s_server() {
    // This ad-hoc probe needs an `openssl s_server` started out of band on :8443.
    // If none is running, SKIP cleanly rather than fail — the Cloudflare test is
    // the real proof; this one is only for isolating CDN-specific rejections.
    let Ok(tcp) = tokio::net::TcpStream::connect("127.0.0.1:8443").await else {
        eprintln!("[local s_server] no server on 127.0.0.1:8443 — skipping (start `openssl s_server -tls1_3` to run)");
        return;
    };
    let mut s = yip_utls::connect(tcp, "localhost", &[0u8; 32], [0u8; 8], false)
        .await
        .expect("tls handshake with local openssl s_server");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write GET");
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await.expect("read response");
    eprintln!(
        "[local s_server] got {n} bytes: {:?}",
        String::from_utf8_lossy(&buf[..n.min(200)])
    );
    assert!(buf[..n].starts_with(b"HTTP/1.1 "));
}
