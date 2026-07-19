//! Async I/O plumbing for the REALITY TLS front (REALITY.1 Task 2).
//!
//! The front must read the raw TLS `ClientHello` off the socket *before*
//! terminating TLS (to run REALITY auth on it). [`read_first_tls_record`]
//! pulls the first TLS record off the wire without interpreting it as TLS.
//!
//! [`PrefixedStream`] (test-only, `#[cfg(test)]`) replays an already-consumed
//! byte prefix so a TLS acceptor can "re-read" a `ClientHello` that was
//! already pulled off the socket. `run_reality_conn`'s authed path no longer
//! needs this at runtime (REALITY.5d): it hands the parsed `ClientHello`
//! bytes straight to `yip_utls::server::emit_server_hello` instead of
//! replaying them onto the socket for a generic TLS acceptor to re-parse —
//! kept here only as a test double for this module's own read/replay tests.
#[cfg(test)]
use std::pin::Pin;
#[cfg(test)]
use std::task::{Context, Poll};

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Wraps `inner` so a previously-consumed byte `prefix` is replayed on read
/// before delegating to `inner`. Test-only (see module docs): production
/// code used this to let a TLS acceptor "re-read" an already-drained
/// `ClientHello`, but REALITY.5d's hand-rolled flow no longer replays onto
/// the socket at all — retained here purely to exercise
/// [`read_first_tls_record`]'s replay-shaped output in this module's tests.
///
/// `AsyncWrite` (and flush/shutdown) delegate straight to `inner` —
/// `prefix` only affects reads.
#[cfg(test)]
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

#[cfg(test)]
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

#[cfg(test)]
impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedStream<S> {
    /// While the buffered `prefix` isn't fully drained, copy from it into
    /// `buf` (respecting `buf.remaining()`) and return without touching
    /// `inner` — even if that only partially fills `buf`. Once the prefix is
    /// drained, every subsequent call delegates straight to `inner`.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
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

#[cfg(test)]
impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefixedStream<S> {
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

/// Outcome of reading the first TLS record for REALITY inspection.
///
/// A malformed/oversized/truncated record is a framing anomaly a real
/// upstream TLS server would answer with its own alert/close — silently
/// dropping the connection here instead would be an observable distinguisher
/// for an active prober (REALITY.1 Task 3 review I-1). So `read_first_tls_record`
/// never itself decides to drop a connection that had bytes on the wire; it
/// hands those bytes back via `Passthrough` so the caller can splice them to
/// the genuine upstream and let it generate the authentic response. Only a
/// connection that produced literally nothing (`Empty`) is safe to drop —
/// there is nothing to replay and nothing a real server would have seen either.
pub enum FirstRecord {
    /// A complete record (header ++ body). `record[5..]` is the handshake message.
    Complete(Vec<u8>),
    /// A framing anomaly (declared body > `MAX_RECORD_BODY_LEN`, or EOF/err mid-record)
    /// AFTER some bytes were consumed. Replay these to the real upstream and splice,
    /// so the genuine server — not us — produces the authentic alert/close (REALITY
    /// indistinguishability). For an oversized record these are just the 5-byte header
    /// (we deliberately do NOT buffer the huge body — the splice streams the rest).
    Passthrough(Vec<u8>),
    /// Nothing was consumed (immediate EOF or hard I/O error before any byte). Drop.
    Empty,
}

/// Result of attempting to fill `buf` completely: either it was, or the
/// connection ended/errored partway through having read `Short(n)` bytes.
///
/// Deliberately not `tokio::io::AsyncReadExt::read_exact`, which on EOF
/// discards the count of bytes actually read (it only reports
/// `UnexpectedEof`) — that count is exactly what `FirstRecord::Passthrough`
/// needs to replay to the real upstream.
enum Read {
    Full,
    Short(usize),
}

/// Fill `buf` from `tcp` by `deadline`, tracking how many bytes were read
/// before a `0`-byte read (EOF), an I/O error, OR the deadline cuts it short.
/// EOF, error, and timeout are treated identically: whatever prefix was
/// consumed is what must be replayed to preserve REALITY indistinguishability
/// — a real upstream server also just holds a half-sent record. The deadline
/// is enforced per read (`timeout_at`), so a stall after some bytes still
/// returns `Short(n)` with `n` intact (a whole-future `timeout` wrapper would
/// cancel the read and lose `n`).
async fn read_full(tcp: &mut TcpStream, buf: &mut [u8], deadline: tokio::time::Instant) -> Read {
    let mut n = 0;
    while n < buf.len() {
        match tokio::time::timeout_at(deadline, tcp.read(&mut buf[n..])).await {
            Ok(Ok(0)) => return Read::Short(n),  // EOF
            Ok(Ok(k)) => n += k,
            Ok(Err(_)) => return Read::Short(n), // I/O error
            Err(_) => return Read::Short(n),     // deadline elapsed mid-read
        }
    }
    Read::Full
}

/// Read exactly one TLS record off `tcp`: the 5-byte header (type,
/// version(2), length(2)) then `length` body bytes. On success, returns the
/// full record (header ++ body) as [`FirstRecord::Complete`] so it can be
/// both parsed (`record[5..]` is the handshake message) and replayed
/// verbatim via [`PrefixedStream`].
///
/// A header claiming a body longer than `MAX_RECORD_BODY_LEN` is a framing
/// anomaly, not silently dropped: returns [`FirstRecord::Passthrough`] with
/// just the 5-byte header (a real `ClientHello` never needs more, and this
/// keeps a malicious/broken header from provoking a large allocation — the
/// oversized body itself is never read here; the caller's splice streams it
/// to the real upstream instead). Likewise, any EOF/error partway through the
/// header or body yields `Passthrough` with whatever prefix was consumed, and
/// only a connection that yielded nothing at all is [`FirstRecord::Empty`].
///
/// Enforces its own `deadline` (per read via `timeout_at`, so a stall after
/// some bytes still returns `Passthrough` with the consumed prefix — a bare
/// `tokio::time::timeout` wrapper on this whole call would instead cancel the
/// read and lose those bytes, dropping a connection a real upstream would have
/// held and answered). Pass `now + HANDSHAKE_TIMEOUT` from `tls_front.rs`.
///
/// A `ClientHello` that is TLS-record-fragmented across multiple records
/// will only have its first fragment returned here. Task 3 treats an
/// unparseable/partial hello as un-authed and splices it to the decoy
/// (fail-safe), so this is acceptable for REALITY.1.
pub async fn read_first_tls_record(
    tcp: &mut TcpStream,
    deadline: tokio::time::Instant,
) -> FirstRecord {
    let mut header = [0u8; 5];
    match read_full(tcp, &mut header, deadline).await {
        Read::Short(0) => return FirstRecord::Empty,
        Read::Short(n) => return FirstRecord::Passthrough(header[..n].to_vec()),
        Read::Full => {}
    }

    // Wire byte math: record length is the big-endian u16 at header[3..5].
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if len > MAX_RECORD_BODY_LEN {
        return FirstRecord::Passthrough(header.to_vec());
    }

    let mut body = vec![0u8; len];
    match read_full(tcp, &mut body, deadline).await {
        Read::Full => {
            let mut record = header.to_vec();
            record.extend_from_slice(&body);
            FirstRecord::Complete(record)
        }
        Read::Short(n) => {
            let mut consumed = header.to_vec();
            consumed.extend_from_slice(&body[..n]);
            FirstRecord::Passthrough(consumed)
        }
    }
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

        let got = read_first_tls_record(
            &mut reader,
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await;
        assert!(
            matches!(&got, FirstRecord::Complete(r) if *r == record),
            "must return Complete(header ++ body)"
        );

        let mut leftover = vec![0u8; extra.len()];
        reader
            .read_exact(&mut leftover)
            .await
            .expect("extra bytes past the record must remain unread");
        assert_eq!(leftover, extra, "extra bytes must be left untouched");
    }

    #[tokio::test]
    async fn read_first_tls_record_partial_then_stall_yields_passthrough_consumed() {
        // A client that sends a partial record then goes silent (no EOF) must
        // yield the consumed prefix as Passthrough once the deadline elapses —
        // NOT be dropped. `writer` stays open (in scope) so there is no EOF;
        // only the deadline ends the read.
        let (mut writer, mut reader) = tcp_pair().await;

        // A well-formed 5-byte header claiming a 37-byte body, then only 10 of
        // those body bytes — then stall.
        let mut partial = vec![0x16, 0x03, 0x01, 0x00, 37];
        partial.extend_from_slice(&[0xABu8; 10]);
        writer.write_all(&partial).await.expect("write partial record");

        let got = read_first_tls_record(
            &mut reader,
            tokio::time::Instant::now() + std::time::Duration::from_millis(150),
        )
        .await;

        match got {
            FirstRecord::Passthrough(bytes) => assert_eq!(
                bytes, partial,
                "a partial-then-stall must replay exactly the consumed prefix"
            ),
            FirstRecord::Complete(_) => panic!("expected Passthrough(consumed), got Complete"),
            FirstRecord::Empty => panic!("expected Passthrough(consumed), got Empty"),
        }
        drop(writer); // keep the connection alive until after the read
    }

    #[tokio::test]
    async fn read_first_tls_record_oversized_length_claim_yields_passthrough_header() {
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

        let got = read_first_tls_record(
            &mut reader,
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await;
        assert!(
            matches!(&got, FirstRecord::Passthrough(b) if *b == header),
            "a length claim above MAX_RECORD_BODY_LEN must yield Passthrough(header only), \
             so the caller can splice the header + rest of the connection to the real upstream"
        );
    }

    #[tokio::test]
    async fn read_first_tls_record_eof_after_partial_header_yields_passthrough() {
        let (mut writer, mut reader) = tcp_pair().await;

        let partial_header = vec![0x16, 0x03];
        writer
            .write_all(&partial_header)
            .await
            .expect("write partial header");
        drop(writer);

        let got = read_first_tls_record(
            &mut reader,
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await;
        assert!(
            matches!(&got, FirstRecord::Passthrough(b) if *b == partial_header),
            "EOF partway through the header must yield Passthrough(bytes actually consumed)"
        );
    }

    #[tokio::test]
    async fn read_first_tls_record_truncated_body_then_fin_yields_passthrough() {
        let (mut writer, mut reader) = tcp_pair().await;

        let full_body = [0xABu8; 37];
        let body_len = u16::try_from(full_body.len()).expect("test body fits in u16");
        let mut header = vec![0x16, 0x03, 0x01];
        header.extend_from_slice(&body_len.to_be_bytes());
        let partial_body = &full_body[..10];

        let mut wire = header.clone();
        wire.extend_from_slice(partial_body);
        writer
            .write_all(&wire)
            .await
            .expect("write header + truncated body");
        drop(writer);

        let mut expected = header;
        expected.extend_from_slice(partial_body);

        let got = read_first_tls_record(
            &mut reader,
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await;
        assert!(
            matches!(&got, FirstRecord::Passthrough(b) if *b == expected),
            "a complete header followed by a truncated body then FIN must yield \
             Passthrough(header ++ partial body)"
        );
    }

    #[tokio::test]
    async fn read_first_tls_record_immediate_eof_yields_empty() {
        let (writer, mut reader) = tcp_pair().await;
        drop(writer);

        let got = read_first_tls_record(
            &mut reader,
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await;
        assert!(
            matches!(got, FirstRecord::Empty),
            "an immediate EOF with nothing consumed must yield Empty"
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
