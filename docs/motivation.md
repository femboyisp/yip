# Why yip exists

yip is built by [FEMBOY CYBER NETWORKS LLC](../README.md#license), an independent entity
registered in Utah.

On May 6, 2026, Utah enacted **Senate Bill 73 — the Online Age Verification Amendments**. As
covered by the [Electronic Frontier Foundation](https://www.eff.org/deeplinks/2026/04/utahs-new-law-regulating-vpns-goes-effect-next-week),
it made Utah the first state to explicitly target the use of VPNs to circumvent geofenced,
government-mandated identity checks — holding a website operator liable when a user reaches
their platform from inside Utah even if that user is masking their location.

The EFF describes the liability trap this creates: a site that cannot reliably guess the
physical origin of a privacy-protected IP faces a choice between banning *every* known
commercial VPN range or forcing intrusive ID/biometric checks on *every* visitor to screen
out hidden Utah users. The law also reaches toward a First Amendment problem by targeting the
act of *providing instructions* for routing around local geofences.

> "Blocking all known VPN and proxy IP addresses is a technical whack-a-mole that likely no
> company can win… The internet is built to, and will always, route around censorship." — EFF

Attacks on VPNs are attacks on the tools that enable digital privacy. The state's approach —
enumerate and block commercial VPN IP ranges — only works against centralized providers with
bannable data-center address blocks. yip's answer is architectural: a decentralized, CA-gated
P2P mesh over opt-in NAT hole-punching and zero-signature obfuscation, with **no
data-center IP blocks to enumerate**. We don't publish instructions for breaking local laws;
we build open systems so that secure, low-latency, private networking stays available
wherever you live.

This is the *why*. The [README](../README.md) is the *what* and *how*, and is honest about
what yip does and does not yet defend.
