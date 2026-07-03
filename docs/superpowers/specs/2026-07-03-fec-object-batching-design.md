# FEC object batching — amortizing the RaptorQ per-object setup across N packets

**Status:** design — awaiting sign-off (implementation not started)
**Scope:** sub-project #1 (core data plane), `yip-transport` FEC egress path +
`bin/yipd` `DataPlane`. Bulk-class egress only.
**Predecessors:** `docs/superpowers/specs/2026-07-02-uring-gso-fate-tags-design.md`
(issue #24, introduced `EgressDatagram { fate, bytes }` and the per-object fate
tag this design reuses), the M5 adaptive-FEC controller, and the M6 reactive-ARQ
loop (`Transport::repair_object` / `FecEncoder::repair_with_id`).

## Goal

Amortize the RaptorQ per-object setup cost. Today yip makes **one RaptorQ object
per packet**, so every egress packet on a lossy link pays a full
`Encoder::new` intermediate-symbol solve (~24 µs/packet, ~80 % of egress CPU per
`cargo run --release -p yip-bench --example pipeline_profile`). Batch **N sealed
ciphertexts into one RaptorQ object** so that fixed setup cost amortizes to
~24 µs / N, and the adaptive controller's repair floor (`.max(1)`) is amortized
from "1 repair symbol per packet" to "≈ N·ratio repair symbols per batch."

This is a **Bulk-only, FEC-active-only** optimization. It deliberately does
nothing for Realtime/Default traffic (latency) and nothing for clean links (the
`repair == 0` bypass already skips the expensive path). See *Interactions* for
the honest scope limit.

## Background (verified in code)

- **One object per packet today.** `DataPlane::on_tun_packet`
  (`bin/yipd/src/dataplane.rs`) seals one inner packet, calls
  `Transport::encode` (`crates/yip-transport/src/lib.rs`) which assigns **one**
  `object_id` (`FecEncoder::next_object_id`, `crates/yip-transport/src/fec.rs`)
  to all symbols of that one packet, and frames each symbol into
  `egress_scratch: Vec<EgressDatagram>`. `Transport::encode` computes
  `source = ceil(ciphertext.len() / symbol_size)` (≈1 for a packet-sized frame),
  asks `controllers[class].repair_count(source)` for the repair count, and calls
  `encoder.encode(ciphertext, params, repair)`.
- **The cost is in `Encoder::new`.** `FecEncoder::encode`
  (`crates/yip-transport/src/fec.rs`) has a fast path: when `repair == 0` **and**
  `oti.sub_blocks() == 1` it emits systematic source symbols directly via
  `source_symbols(...)`, skipping the ~24 µs solve. Whenever `repair > 0` it
  falls through to `Encoder::new(ciphertext, oti)` +
  `get_encoded_packets(repair)` — the full solve, paid **per packet** today.
- **The controller raises repair exactly under loss.** `AdaptiveController`
  (`crates/yip-transport/src/control.rs`): Bulk's `min_ratio` is `0.0` (ARQ
  class), so on a clean link its ratio decays to `0.0` → `repair_count` returns
  `0` → the bypass fires and no `Encoder::new` runs. Under loss `observe_loss`
  jumps the ratio to `loss + 0.05`, so `repair > 0` and the expensive path is
  taken. `repair_count(source) = max(1, ceil(source · ratio))` — note the
  `.max(1)` floor: with `source == 1` today, even a 5 % ratio emits **1 whole
  repair symbol per packet** (100 % redundancy), the worst case for small
  objects.
- **The wire frame is per-symbol and already carries what we need.** `Frame`
  (`crates/yip-wire/src/lib.rs`): `conn_tag: u64`, `object_id: u16`,
  `payload_id: [u8;4]` (RaptorQ SBN+ESI), `flags: u8`, `payload: Vec<u8>`.
  `wire_glue::symbol_to_frame` (`bin/yipd/src/wire_glue.rs`) puts an
  authenticated payload prefix `[u64 counter][u32 object_size]` in front of the
  symbol bytes; `frame_to_symbol` parses `(Symbol, counter, class)` back out.
  **The wire layout does not change** — only what the `counter` field *names*
  (see *Counter model*) and what the object *contents* are.
- **Ingress is per-object.** `on_udp_datagram` deframes → `frame_to_symbol` →
  `detector.on_seen(counter)` → `transport.decode(sym, class)` (per-class
  `FecReassembler` keyed by `class_index`) → on object completion
  `detector.on_delivered(counter)` → `session.open(counter, ciphertext)` →
  `TunWrite`.
- **ARQ is per-object.** `RetxBuffer` (`crates/yip-transport/src/retxbuf.rs`)
  stores `(ciphertext, class, object_id)` keyed by send-counter;
  `Transport::repair_object` → `FecEncoder::repair_with_id` re-encodes with the
  **original** `object_id` so the receiver's existing decoder is topped up.
- **The compatibility gate** is the netns/ARQ suite —
  `arq_recovers_bulk_loss` (`bin/yipd/tests/tunnel_netns.rs` →
  `run-arq-integrity.sh`: 5 % `tc netem` loss, **`MIN_DELIVERY_PCT=98`**, must
  observe ARQ firing). Both peers are one binary and rebuild together in this
  pre-release phase, so an object-content format change needs no version
  negotiation.
- **`nyxpsi` (reference)** `refrences/nyxpsi/src/client.rs` already amortizes
  the same cost by encoding larger objects (`DATA_SIZE = 1300` across
  `MIN_PACKETS..MAX_PACKETS`) and adapting `symbol_size` — confirming the
  approach, though nyxpsi codes one bulk blob rather than concatenating
  independently-sealed packets.

## Non-goals

- **No wire-format change.** `Frame` layout, `HEADER_LEN`, the codec, and
  `symbol_to_frame`'s `[counter][object_size]` prefix are all unchanged. Only the
  *object contents* (a batch container instead of a lone ciphertext) and the
  *meaning* of the frame counter for Bulk objects change.
- **No batching for Realtime/Default.** They stay batch = 1, byte-identical to
  today (latency: their deadlines are 20 ms / 100 ms and they must not wait to
  fill a batch).
- **No batching on clean links.** When Bulk's controller ratio is `0.0`, Bulk
  stays batch = 1 and hits the existing `repair == 0` bypass. Batching engages
  only when `repair > 0`.
- **No change to RaptorQ symbol size or the AEAD/seal boundary.** Each inner
  packet is still sealed independently (its own AEAD nonce/tag); we batch the
  *sealed ciphertexts*, not the plaintext, so the receiver opens each packet
  independently (matches `session.open(counter, ct)` today).
- **No adaptive `symbol_size`** (nyxpsi does this; out of scope — orthogonal
  follow-up).

## Success criteria

- `arq_recovers_bulk_loss` stays **≥ 98 %** delivery with batching on (the FEC-
  safety gate) and still logs "ARQ retransmits: N" (N > 0).
- `pipeline_profile`, extended with a batched Bulk variant, shows encode
  **µs/packet drop ≈ 24/N** at repair > 0 (e.g. N = 8 → ~3 µs/packet vs ~24).
- Lossy-link throughput (a `yip-bench` run under `tc netem` loss) improves
  measurably vs the unbatched baseline; clean-link throughput is **unchanged**
  (bypass path untouched).
- The batch container split/open is enforced at one directly unit-testable
  function (`split_batch_container`), with DoS guards mirroring `fec.rs`.

## Architecture

### 1. The batch container (object contents)

A batched object's plaintext — the byte string handed to `FecEncoder::encode` as
`ciphertext` — is **N sealed ciphertexts concatenated with a 2-byte length
prefix each**:

```
Container := Record+                      // 1..=N records, self-delimiting
Record    := SealedLen ‖ SealedBytes
SealedLen := u16 big-endian               // byte length of SealedBytes
SealedBytes := session.seal(inner_i).ciphertext   // AEAD ct incl. 16-byte tag
```

- **No count field and no per-record counter.** N is recovered by walking
  records until the container is consumed. Record `i`'s AEAD nonce counter is
  **derived** as `base_counter + i`, where `base_counter` is the object counter
  carried in the wire frame's existing `[u64 counter]` prefix (see *Counter
  model* for why the N counters are guaranteed contiguous). This keeps the
  per-packet overhead to just **2 bytes** (`SealedLen`).
- `object_size` (the frame's `[u32 object_size]` prefix, already present) becomes
  the **container** length. It must stay ≤ `MAX_OBJECT_SIZE` (256 KiB,
  `fec.rs`). With ~1.2 KB sealed packets this caps N well above any value we'd
  pick (~200); we bound N far lower for recovery-granularity reasons anyway.
- `object_id` now **names a batch, not a packet.** All N+repair symbols of the
  container share it (they always did — one `encode` call, one `object_id`).

**Format applies to Bulk objects only.** Realtime/Default (and Bulk when
unbatched on a clean link) keep the legacy "one sealed ciphertext = one object,
frame counter = AEAD counter" shape and the receiver opens them exactly as today.
The receiver disambiguates purely on `class` (decoded from `frame.flags` via
`flags_to_class`): **Bulk ⇒ container**, non-Bulk ⇒ legacy single open. Because
non-Bulk is never wrapped, Realtime/Default egress stays byte-identical.

New helpers in `crates/yip-transport/src/fec.rs` (pure, unit-testable):

```rust
/// Concatenate sealed ciphertexts into one batch container.
pub fn build_batch_container(sealed: &[Vec<u8>]) -> Vec<u8>;

/// Split a decoded container back into its sealed-ciphertext records.
/// Returns None on any malformed length (offset overrun, zero-length record,
/// record count over MAX_BATCH_RECORDS) — never panics on attacker bytes.
pub fn split_batch_container(container: &[u8]) -> Option<Vec<&[u8]>>;
```

### 2. Where the accumulator lives, and flush

**The accumulator lives in `DataPlane`** (`bin/yipd/src/dataplane.rs`), not in
`Transport`. Rationale: sealing (`session.seal`) and the object counter live in
`DataPlane`; `Transport` is I/O- and session-free. The accumulator buffers
**plaintext inner packets** (owned copies) — *not* sealed frames — so that all N
seals happen consecutively at flush time and the N AEAD counters are guaranteed
contiguous (see *Counter model*).

New `DataPlane` state:

```rust
/// Buffered plaintext inner packets awaiting a Bulk batch flush.
bulk_batch: Vec<Vec<u8>>,
/// now_ms when the first packet of the current batch was buffered (flush clock).
bulk_batch_started_ms: u64,
/// Second scratch for flush egress (kept separate from egress_scratch so an
/// inline flush inside on_tun_packet and a tick-driven flush don't alias).
flush_scratch: Vec<yip_io::poll::EgressDatagram>,
```

**Routing in `on_tun_packet`:**

```rust
let class = self.transport.classify(inner, self.l2, now_ms);   // new pub method
let batch = class == FlowClass::Bulk && self.transport.bulk_repair_ratio() > 0.0
            && BULK_BATCH_MAX > 1;
if batch {
    if self.bulk_batch.is_empty() { self.bulk_batch_started_ms = now_ms; }
    self.bulk_batch.push(inner.to_vec());
    if self.bulk_batch.len() >= BULK_BATCH_MAX {
        return self.flush_bulk_batch(now_ms);   // inline flush -> &[EgressDatagram]
    }
    return &[];                                  // buffered; nothing to send yet
}
// non-Bulk, or Bulk on a clean link: encode immediately (batch = 1), as today.
self.encode_one(inner, class, now_ms)
```

`classify` is exposed so the routing decision reuses the classifier's single
`observe` side effect; `encode_one` is today's seal→`encode_for_class`→frame
body (refactored so the classifier is not consulted twice).

**Flush interaction with `tick`.** A partial batch must flush on a **~1 ms
deadline** so latency is bounded. Flush produces *many* egress datagrams, which
`tick`'s `Option<&[u8]>` return can't carry, so we add one `Dispatch` method
rather than overloading `tick`:

```rust
pub trait Dispatch {
    fn on_udp(&mut self, dg: &[u8], now_ms: u64) -> DispatchOut<'_>;
    fn on_tun(&mut self, inner: &[u8], now_ms: u64) -> &[EgressDatagram];
    fn tick(&mut self, now_ms: u64) -> Option<&[u8]>;
    /// Flush any time-triggered egress (e.g. a partial Bulk batch past its
    /// deadline). Called by both drivers every poll iteration, after `tick`.
    /// Default impl returns `&[]`.
    fn flush_egress(&mut self, now_ms: u64) -> &[EgressDatagram] { &[] }
}
```

`DataPlane::flush_egress` flushes when
`!bulk_batch.is_empty() && now_ms - bulk_batch_started_ms >= BULK_BATCH_FLUSH_MS`.
Both drivers call it once per loop after `tick`: `PollDriver` sends each `.bytes`
individually (`drain`/tick block in `poll.rs`); `UringDriver` stages them into
its existing `pending_gso` accumulator exactly like `on_tun` output — so the
GSO fate-tag machinery is reused unchanged.

**Deadline resolution caveat.** The poll loop's epoll timeout is 10 ms
(`poll.rs`), so with `flush_egress` alone a partial batch that arrives just as
traffic stalls can wait up to ~10 ms, not 1 ms. Under real Bulk load packets
keep arriving and `BULK_BATCH_MAX` fires first, so this only bites the trailing
partial batch of a burst. Two options, flagged for sign-off: (a) accept ~10 ms
tail latency on the last partial batch (Bulk deadline is 500 ms — well within
budget); or (b) clamp the epoll timeout to the pending flush deadline when
`bulk_batch` is non-empty (small change to the timeout computation in `poll.rs`
/ `uring.rs`). Recommend (a) for v1, (b) as a follow-up if measured tail latency
matters.

### 3. Counter model (the crux)

Each inner packet is still sealed independently, so each has its **own AEAD nonce
counter** (needed to `open` it). The loss detector, `sent_log`, NACK list, and
`RetxBuffer` all operate on a **single monotone counter space** — that is a hard
invariant of `LossDetector` (`crates/yip-transport/src/lossdetect.rs`), which
fills every integer in a `high_counter` gap into its pending set. So we cannot
give Bulk a separate counter space without breaking the shared detector.

**Solution: buffer plaintext, seal at flush, carry the batch's `base` counter on
the wire; the detector reasons over the contiguous range implicitly.**

- Because the accumulator buffers plaintext and `DataPlane` is single-threaded
  (mutex-free design), `flush_bulk_batch` seals the N packets **consecutively**
  with nothing (not even a feedback seal, which only happens in `tick`)
  interleaving. The N AEAD counters are therefore exactly
  `base, base+1, …, base+N-1`.
- The wire frame's `[u64 counter]` prefix carries **`base`** (via
  `symbol_to_frame(conn_tag, sym, base, Bulk)`). The receiver derives record
  `i`'s open-counter as `base + i` — no per-record counter on the wire.
- **Detector, unmodified.** On the receiver:
  - Pre-decode, when a batch symbol arrives, `on_seen(base)` marks `base`
    pending. The interior `base+1..base+N-1` become implied-pending only when a
    later object (counter `≥ base+N`) arrives and `on_seen` gap-fills them —
    exactly the existing mechanism.
  - On batch decode, the receiver knows N (from the container), and calls
    `on_delivered(base + i)` for **every** `i` — resolving the whole range.
    `mark_resolved` advances the low-watermark over the contiguous prefix, so
    `resolved_set` stays small. If a later object already gap-filled the
    interior into pending, `on_delivered` clears it; if not, `is_resolved`
    short-circuits the future gap-fill. Either way no false "missing."
  - If the batch is **lost entirely** (never decodes), the interior stays
    pending → after `grace_ms` the range `base..base+N-1` is promoted to
    `missing` — precisely the signal ARQ needs.

**`sent_log` and `RetxBuffer` gain span awareness.**

- `flush_bulk_batch` inserts the whole range into `sent_log`:
  `for i in 0..N { sent_log.insert(base + i, Bulk); }` (the 4096-cap ring
  absorbs this) so the ingress loss-attribution loop
  (`sent_log.get(c) → class`) counts each lost interior counter against Bulk.
- `RetxBuffer::put` grows a `span: u16` field; the batch is stored once keyed by
  `base` with `span = N` and the container bytes + `object_id`. `RetxBuffer::get`
  becomes a **range** lookup: a NACKed counter `c` finds the batch whose
  `[base, base+span)` contains it. The ARQ loop in `on_udp_datagram` **dedupes
  by `object_id`** within one control-packet handling so a batch whose whole
  range was NACKed is retransmitted **once**, not N times.

For non-Bulk (span 1) every one of these reduces to today's exact behavior.

### 4. Repair scaling — no controller change

`repair_count(source_symbols)` already scales with the source-symbol count, so
feeding it the **batch's** source count does the right thing:

```rust
// in a new Transport::encode_batch(container, now_ms) -> Vec<Symbol>
let source = ceil(container.len() / symbol_size);       // ≈ N for N packets
let repair = self.controllers[Bulk].repair_count(source);   // ceil(N·ratio), min 1
let syms = self.encoder.encode(container, Bulk.params(), repair);
```

- Repair symbols are now emitted **per object (batch)**, not per packet — the
  literal ask of the design. At ratio 0.05, N = 8 → `ceil(8·0.05) = 1` repair
  symbol for **8** packets (12.5 % overhead) vs `max(1, ceil(1·0.05)) = 1` per
  packet (100 % overhead) today. Batching thus *also* fixes the `.max(1)`
  small-object floor — a real secondary win.
- The controller itself (`observe_loss`, AIMD, `min_ratio`) is untouched; only
  the `source` it is fed changes. `bulk_repair_ratio()` (already public) is the
  gate `DataPlane` reads to decide whether to batch at all.

### 5. Ingress decode path

In `on_udp_datagram`'s Data branch, after `transport.decode` returns a completed
object and `class == Bulk`:

```rust
detector.on_seen(base, now_ms);          // base = frame counter (already done)
let container = /* decoded object bytes */;
let records = split_batch_container(&container)?;   // None -> drop, no panic
for (i, sealed) in records.iter().enumerate() {
    let ctr = base + (i as u64);
    let inner = session.open(ctr, sealed)?;         // per-packet AEAD open
    detector.on_delivered(ctr);
    // TUN-write inner (L2 MAC learning as today)
}
```

Because `Outcome::TunWrite` returns a single borrowed slice today, ingress must
either (a) emit one `Outcome` carrying multiple inner packets, or (b) write each
inner packet to TUN inline and return `Outcome::None`. Recommend **(b)** — a new
`DataPlane` capability to write straight to the TUN fd for the multi-packet case,
mirroring how egress already loops. (The single-packet non-Bulk path keeps
returning `TunWrite`.) This is the one non-trivial ingress plumbing change and is
called out as a review point.

DoS guards mirror `fec.rs`: `split_batch_container` rejects zero-length records,
offset overruns, and `> MAX_BATCH_RECORDS`; the derived counter `base + i` uses
`checked_add`.

### 6. Configuration

Add two fields to `FlowParams` (`crates/yip-transport/src/lib.rs`) so the policy
is class-scoped and unit-testable, defaulting non-Bulk to "no batching":

```rust
pub struct FlowParams {
    // …existing…
    pub batch_max: u16,        // max packets per FEC object (1 = no batching)
    pub batch_deadline: Duration,
}
```

Defaults: **Bulk `batch_max = 8`, `batch_deadline = 1 ms`**; Realtime/Default
`batch_max = 1` (unchanged behavior). `DataPlane` reads
`FlowClass::Bulk.params().batch_max` for `BULK_BATCH_MAX` and
`.batch_deadline` for `BULK_BATCH_FLUSH_MS`. An optional `YIP_BULK_BATCH_MAX`
env override (mirroring the existing `YIP_USE_URING` / `YIP_URING_BUSYPOLL`
pattern) is a nice-to-have ops escape hatch.

## Alternatives considered

- **Single AEAD seal per batch** (concat N *plaintext* packets, seal once, split
  after one `open`). Simplest for counters — one object = one counter = one AEAD
  op, detector/`sent_log`/`RetxBuffer` fully unchanged, and *less* AEAD overhead
  (one 16-byte tag, not N). **Rejected** because it violates the per-packet
  crypto boundary the rest of the data plane assumes (the receiver would open
  once then split, rather than `open` each) and it couples all N packets into one
  AEAD failure domain. The chosen "seal each, batch the sealed frames" model
  keeps `session.open(counter, ct)` per packet and matches the existing ingress
  contract; the contiguity trick (buffer plaintext, seal consecutively at flush)
  recovers most of the counter simplicity anyway. Documented per the brief.
- **Accumulator in `Transport`.** Rejected: `Transport` has no session, so it
  can't seal, and buffering pre-seal plaintext there would force the seal step
  and the object counter down into `Transport` too — a worse layering than
  keeping all session/counter state in `DataPlane`.
- **Separate object-counter space for Bulk.** Rejected: `LossDetector` assumes a
  single monotone space shared with non-Bulk and control; a second space breaks
  gap detection on mixed-class tunnels.

## Recovery-granularity tradeoff

A batch is **more all-or-nothing**. A RaptorQ object with N source + R repair
symbols decodes iff the receiver gets ≳ N of the N+R symbols; if aggregate loss
on the object exceeds R, the **whole batch (N packets)** is undecodable, versus
losing a single packet today.

Mitigating factors:

- **GSO fate tags decorrelate the object's symbols.** All N+R symbols share one
  `object_id` = one `fate`, so the GSO driver (issue #24) refuses to coalesce
  them into one skb — they go out in *separate* datagrams. A single skb drop
  therefore cannot take out the batch; only genuinely independent aggregate loss
  exceeding R can. So the all-or-nothing risk is about *aggregate* loss > R, not
  a correlated burst.
- **ARQ backstops it.** Bulk has `arq = true`. A batch that exceeds R and stalls
  is NACKed (its whole counter range) and `repair_object` retransmits fresh
  repair under the same `object_id`, topping up the receiver's decoder. This is
  exactly what `arq_recovers_bulk_loss` exercises and gates at 98 %.
- **The repair budget scales with N.** Because `repair = ceil(N·ratio)`, a
  bigger batch gets proportionally more repair, holding expected residual loss
  roughly constant; only the *variance* grows.

**Recommended defaults: N = 8, `batch_deadline = 1 ms`, plus the controller's
own headroom (`loss + 0.05`).** N = 8 cuts encode cost ~8× (24 → ~3 µs/packet)
while keeping the blast radius modest (8 packets) and the container small
(~9.7 KB, ~8 source symbols, single source block). N = 16 is a reasonable
higher-throughput / higher-loss tuning; avoid N ≫ 32 (blast radius + tail
latency + `MAX_OBJECT_SIZE`). Keep the `repair_count` `.max(1)` floor so even a
low ratio yields ≥1 repair symbol per batch.

## Interactions

- **(a) GSO fate-tags (#24).** Compatible. A batched object is N+R same-fate
  symbols; GSO correctly refuses to coalesce them *within* the object (same
  `object_id`) and still coalesces *across* batches (distinct `object_id`s). Note
  batching produces **fewer distinct objects per poll** (N packets → 1 object),
  so there are fewer distinct fates and thus fewer cross-object GSO coalescing
  opportunities within a Bulk flow — the two optimizations are partly
  substitutive, not additive. No correctness interaction; `flush_egress` output
  rides the same `pending_gso` path.
- **(b) ARQ retransmit.** `repair_object` / `repair_with_id` re-encode by
  `object_id`, which is preserved for a batch (one `object_id` for the whole
  container). A NACK now retransmits **a whole batch's repair** (recovering all N
  packets at once — fewer, larger retransmits). Object-id preservation holds
  unchanged. New requirements: `RetxBuffer` stores the container with a `span`
  and does range lookup; the ARQ loop dedupes retransmits by `object_id`.
  `RetxBuffer` entries are now ~N× larger (container bytes) — with N = 8 and the
  16 384-entry cap that is bounded and fine, but worth a note.
- **(c) The `repair == 0` bypass — honest scope limit.** On a **clean** link
  Bulk's ratio is `0.0`, so `DataPlane` does **not** batch (batch = 1) and
  `FecEncoder::encode` takes the bypass — no `Encoder::new`, nothing to
  amortize. **Batching therefore does nothing for clean-link throughput.** It
  helps only when `repair > 0`, i.e. Bulk under measured loss. Realtime/Default
  keep a proactive repair floor (always `repair > 0`, always the `Encoder` path)
  but are deliberately **not** batched (latency), so they keep paying
  ~24 µs/packet by design. Net: the win is confined to **Bulk-under-loss
  egress** — stated plainly so no one expects a clean-link speedup.

## Component / file changes

- `crates/yip-transport/src/fec.rs`
  - `build_batch_container` / `split_batch_container` (+ `MAX_BATCH_RECORDS`,
    DoS guards, unit tests). No change to `FecEncoder`/`FecReassembler`.
- `crates/yip-transport/src/lib.rs`
  - `FlowParams`: add `batch_max: u16`, `batch_deadline: Duration`; set Bulk
    `= (8, 1ms)`, others `= (1, _)`.
  - `Transport`: add `pub fn classify(&mut self, inner, l2, now) -> FlowClass`
    and `pub fn encode_batch(&mut self, container, now) -> Vec<Symbol>` (Bulk
    controller, fresh `object_id`); optionally `encode_for_class` to avoid double
    classification for non-Bulk.
- `crates/yip-transport/src/retxbuf.rs`
  - `Entry.span: u16`; `put(..., span)`; `get` range lookup over `[base, base+span)`.
- `crates/yip-io/src/poll.rs`
  - `Dispatch::flush_egress(&mut self, now) -> &[EgressDatagram]` (default `&[]`);
    `PollDriver` calls it after `tick` and sends each `.bytes`.
- `crates/yip-io/src/uring.rs`
  - `UringDriver` calls `flush_egress` after `tick`, staging output into the
    existing `pending_gso` (reuses fate-tag coalescing verbatim).
- `bin/yipd/src/dataplane.rs`
  - Accumulator fields (`bulk_batch`, `bulk_batch_started_ms`, `flush_scratch`);
    routing in `on_tun_packet`; `flush_bulk_batch`; `flush_egress` impl;
    range `sent_log` insert; `RetxBuffer::put(span)`; ARQ `object_id` dedupe;
    Bulk ingress container split + per-record `open` + multi-packet TUN write.
- `bin/yipd/src/wire_glue.rs` — unchanged (`symbol_to_frame`/`frame_to_symbol`
  already carry `counter` + `object_size`; `counter` now means `base` for Bulk).
- `crates/yip-wire/` — unchanged.
- `crates/yip-bench/examples/pipeline_profile.rs` — add a batched-Bulk variant
  reporting encode µs/packet at N ∈ {1, 4, 8, 16}.

## Data flow

1. TUN frame → `on_tun_packet` → `classify`. If Bulk **and**
   `bulk_repair_ratio() > 0` **and** `batch_max > 1`: copy plaintext into
   `bulk_batch`; if full → `flush_bulk_batch`, else return `&[]`.
2. Otherwise (non-Bulk, or Bulk clean): seal → `encode` (batch = 1, bypass when
   `repair == 0`) → frame → `&[EgressDatagram]` as today.
3. `flush_bulk_batch(now)`: seal all buffered packets consecutively →
   contiguous `base..base+N-1`; `build_batch_container` → `encode_batch` →
   `sent_log` range insert + `retx.put(base, container, Bulk, object_id, span=N)`
   → frame each symbol with `counter = base`, `fate = object_id` →
   `&[EgressDatagram]`.
4. `flush_egress(now)` (both drivers, post-`tick`): flush a partial batch past
   `batch_deadline`.
5. Egress send: `PollDriver` per-datagram; `UringDriver` via `pending_gso`
   (fate-safe GSO across batches).
6. Ingress: deframe → `on_seen(base)` → `decode`; on completion, Bulk ⇒
   `split_batch_container` → per-record `open(base+i)` + `on_delivered(base+i)` +
   TUN-write each; non-Bulk ⇒ legacy single `open`/`TunWrite`.
7. ARQ: NACK on any of `base..base+N-1` → range lookup finds the batch →
   `repair_object` (same `object_id`) → dedup by `object_id`.

## Testing / validation plan

**Unit (pure, no I/O):**
- `batch_container_roundtrips` — `split(build(v)) == v` for varied N and lengths.
- `split_batch_container_rejects_malformed` — zero-length record, offset
  overrun, over-`MAX_BATCH_RECORDS` → `None`, no panic (mirrors the `fec.rs`
  malformed-input tests).
- `retxbuf_range_lookup_finds_batch` — `put(base, .., span=N)`; `get(base+k)`
  for `0 ≤ k < N` returns the batch; `get(base+N)` returns `None`.
- `repair_count_scales_to_batch_source` — `repair_count(8)` at ratio 0.05 gives
  1, not 8; confirms per-object (not per-packet) repair.
- Detector range resolution: seal a 4-packet batch, feed `on_seen(base)` then
  `on_delivered(base..base+4)`; a following object at `base+4` must not report
  the interior missing; a *dropped* batch must report the range after grace.

**`DataPlane` integration (in-process pair, existing `dataplane_pair` harness):**
- `bulk_batch_roundtrips_all_packets` — feed N Bulk packets (force ratio > 0 via
  `observe_loss`); assert one flush emits one `object_id`, and B recovers **all
  N** inner packets in order.
- `bulk_batch_flushes_on_deadline` — feed 3 (< N) Bulk packets, then
  `flush_egress(now + 2ms)` emits the partial batch; all 3 recover.
- `non_bulk_unbatched_and_byte_identical` — Realtime/Default egress is unchanged
  (single object per packet, legacy open).
- `clean_link_bulk_not_batched` — with ratio 0, Bulk stays batch = 1 (bypass).

**Regression gate (compatibility):**
- `arq_recovers_bulk_loss` (5 % `tc netem`, `MIN_DELIVERY_PCT=98`) under **both**
  `poll` and `uring` — must stay ≥ 98 % and still log ARQ firing. This is the
  hard sign-off gate.
- `ping_across_yipd_tunnel{,_under_loss}`, `l2_tap_ping_or_arp_across_tunnel` —
  no regression.

**Benchmarks:**
- `pipeline_profile` batched variant: encode µs/packet at N ∈ {1,4,8,16};
  expect ≈ 24/N at repair > 0.
- `yip-bench` throughput under `tc netem` loss, batched vs baseline (expect a
  win); clean-link throughput (expect unchanged).

## Fallback & rollout

- **Kill switch:** `batch_max = 1` (per-class default for non-Bulk, and settable
  for Bulk via `YIP_BULK_BATCH_MAX=1`) disables batching entirely and reverts to
  today's one-object-per-packet path — a clean, structural off switch.
- **Sequence:** (1) land `fec.rs` container helpers + `retxbuf` span + `FlowParams`
  fields (no behavior change while `batch_max` stays 1); (2) land the
  `Dispatch::flush_egress` default + driver call sites (no-op default); (3) land
  the `DataPlane` accumulator + Bulk ingress split behind Bulk `batch_max = 8`;
  (4) run the full validation plan incl. the manual `arq_recovers_bulk_loss` +
  bench re-run; (5) tune N from bench data.
- **Both peers rebuild together** (pre-release) — no version negotiation needed
  for the object-content change.

## Open questions / risks

| Risk / question | Notes |
|---|---|
| **All-or-nothing blast radius.** Losing > R symbols of a batch loses N packets at once. | Mitigated by GSO fate decorrelation + ARQ + N-scaled repair; recommend conservative N = 8. Sign-off on N default. |
| **Partial-batch tail latency** bounded by the 10 ms epoll timeout, not 1 ms, when traffic stalls mid-batch. | Recommend accepting it for v1 (Bulk deadline is 500 ms); option (b) clamps the epoll timeout — decide at sign-off. |
| **Ingress multi-packet TUN write.** `Outcome::TunWrite` returns one slice; the batch decode writes N inner packets. | Recommend writing each inline (return `Outcome::None`); the one non-trivial ingress change — review the borrow/scratch handling. |
| **ARQ dedupe by `object_id`.** A fully-NACKed batch range must retransmit the batch once. | Must dedupe within one control-packet handling; add a regression test. |
| **`sent_log` range insert** adds N entries per batch to the 4096-cap ring. | Bounded/cheap, but shortens the log's counter horizon under heavy Bulk load; confirm attribution still accurate. |
| **`RetxBuffer` entries are ~N× larger** (container bytes). | Bounded by the 16 384-entry cap; note memory. |
| **Contiguity assumption** (N seals with nothing interleaving) relies on `DataPlane` being single-threaded and feedback seals happening only in `tick`. | True today (mutex-free loop); flagged so a future concurrent seal path doesn't silently break the `base + i` derivation. |
| **N / deadline / per-class policy** are first-guess constants. | Tune from the bench re-run; per-class `batch_max` in `FlowParams` makes this data-driven. |

## Summary

Batch **N = 8** independently-sealed Bulk ciphertexts into one RaptorQ object
(`[u16 len][sealed]…` container, N derived by walking records, per-packet AEAD
counter = `base + i` from the frame's existing counter field), flushing on
`min(N, ~1 ms)`. The accumulator lives in `DataPlane` and buffers *plaintext* so
the N seals are consecutive and their counters contiguous, keeping the shared
`LossDetector` unmodified; `sent_log`/`RetxBuffer`/ARQ gain a span so a NACK
recovers the whole batch under its preserved `object_id`. The adaptive controller
needs **no change** — feeding it the batch's source count scales repair per
object and amortizes the `.max(1)` floor. **Honest scope limit: this does nothing
for clean-link throughput** (the `repair == 0` bypass already skips the cost) and
nothing for un-batched Realtime/Default; the win is confined to Bulk-under-loss
egress, where encode drops from ~24 to ~24/N µs/packet. Top risks: batch
all-or-nothing blast radius (mitigated by GSO decorrelation + ARQ), partial-batch
tail latency, and the ingress multi-packet TUN write.

**Follow-up issues worth filing:**
1. Adaptive `symbol_size` per link quality (nyxpsi-style) — orthogonal FEC win.
2. Optional epoll-timeout clamp to the pending flush deadline (tail-latency knob).
3. Extend batching to the ARQ retransmit egress path if it ever wants GSO.
4. `HashSet`/index-based `RetxBuffer` range lookup if profiling shows the linear
   span scan matters under heavy ARQ.
