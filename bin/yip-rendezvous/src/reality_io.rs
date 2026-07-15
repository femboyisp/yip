//! Async I/O plumbing for the REALITY TLS front (REALITY.1 Task 2).
//!
//! The front must read the raw TLS `ClientHello` off the socket *before*
//! terminating TLS (to run REALITY auth on it), then hand the connection to
//! the TLS acceptor as if nothing had been read. Two primitives make that
//! possible: [`read_first_tls_record`] pulls the first TLS record off the
//! wire without interpreting it as TLS, and [`PrefixedStream`] replays an
//! already-consumed byte prefix so `tokio_boring::accept` can "re-read" the
//! `ClientHello` it needs from a socket that has already had it drained.
//! Wired into the async TLS front by `tls_front::run_reality_conn`
//! (REALITY.1 Task 3).
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Wraps `inner` so a previously-consumed byte `prefix` is replayed on read
/// before delegating to `inner`. Lets a TLS acceptor "re-read" a
/// `ClientHello` that was already pulled off the socket for REALITY auth
/// inspection: `PrefixedStream::new(record_bytes, tcp)` handed to
/// `tokio_boring::accept` makes BoringSSL see the ClientHello followed
/// seamlessly by the rest of the live connection.
///
/// `AsyncWrite` (and flush/shutdown) delegate straight to `inner` —
/// `prefix` only affects reads.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// Wrap `inner`, replaying `prefix` first on every `AsyncRead` before
    /// falling through to `inner`.
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    /// While the buffered `prefix` isn't fully drained, copy from it into
    /// `buf` (respecting `buf.remaining()`) and return without touching
    /// `inner` — even if that only partially fills `buf`. Once the prefix is
    /// drained, every subsequent call delegates straight to `inner`.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let remaining = &this.prefix[this.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Largest TLS-record body this reader will accept (a `ClientHello` never
/// needs more). Bounds the allocation in `read_first_tls_record` against a
/// header lying about a huge record.
const MAX_RECORD_BODY_LEN: usize = 16_384;

/// Read exactly one TLS record off `tcp`: the 5-byte header (type,
/// version(2), length(2)) then `length` body bytes. Returns the full record
/// (header ++ body) so it can be both parsed (`record[5..]` is the handshake
/// message) and replayed verbatim via [`PrefixedStream`].
///
/// Rejects a header claiming a body longer than `MAX_RECORD_BODY_LEN` with an
/// `InvalidData` error — a real `ClientHello` never needs more, and this
/// keeps a malicious/broken header from provoking a large allocation.
///
/// Does not itself enforce a timeout: the caller wraps this in
/// `tokio::time::timeout` (mirroring `HANDSHAKE_TIMEOUT` in
/// `tls_front.rs`) so a stalled client can't park the read forever.
///
/// A `ClientHello` that is TLS-record-fragmented across multiple records
/// will only have its first fragment returned here. Task 3 treats an
/// unparseable/partial hello as un-authed and forwards it to the decoy
/// (fail-safe), so this is acceptable for REALITY.1.
pub async fn read_first_tls_record(tcp: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    tcp.read_exact(&mut header).await?;
    // Wire byte math: record length is the big-endian u16 at header[3..5].
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if len > MAX_RECORD_BODY_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("TLS record body too large: {len} > {MAX_RECORD_BODY_LEN}"),
        ));
    }
    let mut record = Vec::with_capacity(5 + len);
    record.extend_from_slice(&header);
    record.resize(5 + len, 0u8);
    tcp.read_exact(&mut record[5..]).await?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A connected loopback TCP pair, since `read_first_tls_record` is typed
    /// to `&mut TcpStream` (matching its real call site) rather than a
    /// generic `AsyncRead`.
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener has a local addr");
        let (connected, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (
            connected.expect("connect to loopback listener"),
            accepted.expect("accept loopback connection").0,
        )
    }

    #[tokio::test]
    async fn read_first_tls_record_returns_header_plus_body_and_leaves_extra_unread() {
        let (mut writer, mut reader) = tcp_pair().await;

        let body = vec![0xABu8; 37];
        let body_len = u16::try_from(body.len()).expect("test body fits in u16");
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&body_len.to_be_bytes());
        record.extend_from_slice(&body);
        let extra = vec![0xEEu8; 5];

        let mut wire = record.clone();
        wire.extend_from_slice(&extra);
        writer
            .write_all(&wire)
            .await
            .expect("write synthetic record");

        let got = read_first_tls_record(&mut reader)
            .await
            .expect("well-formed record must be read");
        assert_eq!(got, record, "must return exactly header ++ body");

        let mut leftover = vec![0u8; extra.len()];
        reader
            .read_exact(&mut leftover)
            .await
            .expect("extra bytes past the record must remain unread");
        assert_eq!(leftover, extra, "extra bytes must be left untouched");
    }

    #[tokio::test]
    async fn read_first_tls_record_rejects_oversized_length_claim() {
        let (mut writer, mut reader) = tcp_pair().await;

        let claimed_len =
            u16::try_from(MAX_RECORD_BODY_LEN + 1).expect("MAX_RECORD_BODY_LEN + 1 fits in u16");
        let mut header = vec![0x16, 0x03, 0x01];
        header.extend_from_slice(&claimed_len.to_be_bytes());
        writer
            .write_all(&header)
            .await
            .expect("write oversized-claim header");
        // Dropping the writer half closes the connection, so a (buggy)
        // implementation that tried to read the (never-sent) oversized body
        // fails fast on EOF instead of hanging the test.
        drop(writer);

        let result = read_first_tls_record(&mut reader).await;
        assert!(
            result.is_err(),
            "a length claim above MAX_RECORD_BODY_LEN must be rejected"
        );
    }

    #[tokio::test]
    async fn prefixed_stream_read_yields_prefix_then_live_bytes_across_small_reads() {
        let (client_end, server_end) = tokio::io::duplex(64);
        let prefix = b"hello-".to_vec();
        let live = b"world!".to_vec();

        let mut server_end = server_end;
        let live_clone = live.clone();
        let writer = tokio::spawn(async move {
            server_end
                .write_all(&live_clone)
                .await
                .expect("write live bytes from the server end");
            server_end
        });

        let mut stream = PrefixedStream::new(prefix.clone(), client_end);
        let mut got = Vec::new();
        // A tiny read buffer forces the prefix to drain over several polls,
        // proving it doesn't get skipped or truncated.
        let mut chunk = [0u8; 3];
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .expect("read from PrefixedStream");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
            if got.len() >= prefix.len() + live.len() {
                break;
            }
        }

        let mut expected = prefix;
        expected.extend_from_slice(&live);
        assert_eq!(
            got, expected,
            "must yield prefix bytes then live bytes, in order"
        );

        // Keep the writer task's handle alive until it finishes, so the test
        // doesn't race the spawned write.
        writer.await.expect("writer task must not panic");
    }

    #[tokio::test]
    async fn prefixed_stream_write_reaches_inner() {
        let (client_end, mut server_end) = tokio::io::duplex(64);
        let mut stream = PrefixedStream::new(Vec::new(), client_end);

        let payload = b"written-through".to_vec();
        stream
            .write_all(&payload)
            .await
            .expect("write through PrefixedStream");
        stream.flush().await.expect("flush PrefixedStream");
        drop(stream);

        let mut got = vec![0u8; payload.len()];
        server_end
            .read_exact(&mut got)
            .await
            .expect("bytes written to PrefixedStream must arrive on inner");
        assert_eq!(got, payload);
    }
}
