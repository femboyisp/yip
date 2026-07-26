## What & why

<!-- One or two sentences: what does this change, and why? Link the issue it closes. -->

Closes #

## Checklist

- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` pass
- [ ] Added/updated tests that would fail without this change (boundary conditions included)
- [ ] Ran the relevant `bin/yipd/tests/run-netns-*.sh` under `sudo` on both drivers, if the change touches the data/control plane
- [ ] Updated docs / CHANGELOG if behavior or config changed
- [ ] No new `unsafe` outside `yip-io`; no bare `#[allow]`; no `as` numeric casts

> [!IMPORTANT]
> Security-relevant change? See [`SECURITY.md`](../SECURITY.md) before disclosing details.
