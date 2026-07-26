# Contributing to yip

Contributions are welcome — code, review, testing, docs, and real-world deployment reports.
yip is pre-1.0 and moves fast; the bar is high on correctness and honesty, relaxed on
everything else. Be kind, be rigorous, have fun.

## Getting set up

Linux, a recent stable Rust toolchain, plus a C toolchain and `cmake` (the REALITY
TLS-mimicry crate links BoringSSL).

```sh
git clone https://github.com/femboyisp/yip && cd yip
cargo build --release --workspace
cargo test --workspace            # unit tests
pre-commit install                # runs fmt/clippy/tests/hygiene before each commit
```

## What "passing" means

Before you open a PR, all of these must be green:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The **network-namespace integration tests** need root and exercise both I/O drivers — they
run in CI and are how end-to-end behavior is actually proven. Run the ones near your change:

```sh
sudo bash bin/yipd/tests/run-netns-tunnel.sh "$(pwd)/target/release/yipd"
sudo YIP_USE_URING=1 bash bin/yipd/tests/run-netns-tunnel.sh "$(pwd)/target/release/yipd"
```

> [!WARNING]
> A plain `cargo test --workspace` **skips** the netns tests (they no-op without root), so a
> green unprivileged run is *not* proof the privileged paths work. Run them under `sudo`, or
> rely on the CI `integration` workflow.

## Code style

yip follows a set of [coding
guidelines](https://github.com/mullvad/mullvadvpn-app/blob/main/CODING_GUIDELINES.md):

- The workspace lint set with `-D warnings`. No bare `#[allow]` — use `#[expect(reason = "…")]`.
- No `as` casts for numeric conversion — use `From`/`TryFrom`. (The one exception is the
  enum-discriminant idiom `PacketType::X as u8` for wire serialization.)
- `#![forbid(unsafe_code)]` on every crate except `yip-io` (the packet-I/O layer). Any `unsafe`
  there carries a `// SAFETY:` comment.
- Pinned dependency versions; `cargo-deny` and `cargo-shear` run in CI.
- Prefer small, focused files and functions. When a file grows unwieldy, splitting it is fair
  game.

## Tests are part of the change

- New behavior needs a test that would fail without it. Boundary conditions especially —
  the mutation-testing job (`cargo-mutants`) will find a `<` that should be `<=` that no test
  distinguishes.
- Don't weaken or delete an existing test to make a change pass.
- Integration ("money") tests should carry a *positive* witness of the property under test,
  not just "nothing crashed."

## Pull requests

- Branch off `main`; keep PRs focused. A short description of *what* and *why* beats a long one.
- Reference the issue you're closing. If you found a new problem, file an issue too.
- CI must be green (fmt, clippy, tests, coverage, mutation, the nDPI DPI-undetectability gate,
  and the netns integration suite). Flaky-under-load netns tests are handled explicitly —
  don't paper over a real failure as flakiness.
- Security-relevant changes: see [`SECURITY.md`](SECURITY.md) before disclosing anything.

## Licensing

yip is [AGPL-3.0-or-later](LICENSE). By contributing you agree your contribution is licensed
under the same terms.
