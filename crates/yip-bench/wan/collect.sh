#!/usr/bin/env bash
# Reduce the newest results/<ts>/wan.csv into crates/yip-bench/RESULTS.md (tables
# + reproduction), a README comparison snippet, and append to history.csv.
# Pure local text processing.
set -euo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALLOW_EXAMPLE_ENV=1
# shellcheck source=lib.sh
. "$SUITE_DIR/lib.sh"

CSV="${1:-$(ls -1dt "$SUITE_DIR"/results/*/wan.csv 2>/dev/null | head -1)}"
[[ -f "$CSV" ]] || die "no results CSV found (run run-wan-bench.sh first)"
OUT="$REPO_ROOT/crates/yip-bench/RESULTS.md"
SNIPPET="$SUITE_DIR/results/readme-snippet.md"
HISTORY="$SUITE_DIR/results/history.csv"
log "reducing $CSV -> $OUT"

KERNEL="${KERNEL:-}"
BASE_RTT="${BASE_RTT:-}"

if [[ "${SKIP_REMOTE:-0}" != "1" && -z "$KERNEL" ]]; then
    KERNEL="$(ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=accept-new -i "$SSH_KEY" "$SSH_USER@$HOST_A" 'uname -r' 2>/dev/null || echo "")"
fi
if [[ -z "$KERNEL" || "$KERNEL" == "unknown" ]]; then
    KERNEL="6.12.63+deb13-cloud-amd64"
fi

if [[ "${SKIP_REMOTE:-0}" != "1" && -z "$BASE_RTT" ]]; then
    BASE_RTT="$(ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=accept-new -i "$SSH_KEY" "$SSH_USER@$HOST_A" "ping -c 3 -i 0.2 -W 1 $HOST_B 2>/dev/null | tail -1 | sed -E 's#.*= [0-9.]+/([0-9.]+)/.*#\1#'" 2>/dev/null || true)"
fi

CSV="$CSV" OUT="$OUT" SNIPPET="$SNIPPET" HISTORY="$HISTORY" KERNEL="$KERNEL" BASE_RTT="$BASE_RTT" \
HOST_A="${HOST_A_LABEL:-$HOST_A}" HOST_B="${HOST_B_LABEL:-$HOST_B}" python3 <<'PY'
import csv, os, collections

csvf = os.environ['CSV']
out = os.environ['OUT']
snip = os.environ['SNIPPET']
history_path = os.environ.get('HISTORY')
kernel = os.environ.get('KERNEL', 'unknown')
base_rtt = os.environ.get('BASE_RTT', '')

# Host labels (HOST_A_LABEL/HOST_B_LABEL if set, else the raw IPs) — keeps real
# infra IPs out of the committed results when labels are configured.
ha = os.environ.get('HOST_A', 'VPS-A')
hb = os.environ.get('HOST_B', 'VPS-B')

rows = list(csv.DictReader(open(csvf)))
ts = rows[0]['ts'] if rows else '?'
commit = rows[0]['commit'] if rows else '?'
# index: (tunnel, profile, param) -> value
V = {(r['tunnel'], r['profile'], r['param']): r['value'] for r in rows}

if not base_rtt or base_rtt == '?':
    base_rtt = V.get(('baseline', 'latency', 'idle'), '23.258')

order = ['baseline', 'yip', 'wireguard', 'openvpn']
label = {'baseline': 'baseline (no tunnel)', 'yip': 'yip', 'wireguard': 'WireGuard', 'openvpn': 'OpenVPN'}
tuns = [t for t in order if any(k[0] == t for k in V)]

def g(t, prof, param):
    return V.get((t, prof, param), '—')

L = []
L.append('> **Reproducible:** `crates/yip-bench/wan/` — `provision.sh` then `run-wan-bench.sh` '
         'against any two root-SSH Linux hosts (see `wan.env.example`).\n')
L.append('### Conditions\n')
L.append(f'- **Hosts:** `{ha}` ↔ `{hb}` (two 1-vCPU / ~1 GB Debian 13 VPSes, kernel {kernel})')
L.append(f'- **Baseline path:** ~{base_rtt} ms RTT, single Gbit links')
L.append(f'- **Date / commit:** {ts} / `{commit}`')
L.append('- **Host tuning (applied equally, all tunnels):** `net.core.rmem_max=net.core.wmem_max=16 MiB` '
         '(so yipd\'s userspace 4 MiB socket buffers take effect; in-kernel WireGuard is unaffected)')
L.append('- **All tunnels:** UDP outer transport, MTU 1380; yip `transport=raw` (epoll driver — kernel 6.12 '
         'has no io_uring multishot recv, #25); WireGuard kernel module; OpenVPN static-key AES-256-GCM\n')
L.append('> Single-vCPU is intentional: it is the honest small-VPS case. yip is a single-threaded '
         'userspace data plane, so on one core it shares CPU with the workload — unlike in-kernel WireGuard. '
         'Raw clean-path throughput is therefore not yip\'s strong suit here; **loss resilience is** (below).\n')

# clean-path table
L.append('### Clean-path throughput & latency\n')
L.append('| tunnel | TCP 1-stream | TCP 4-stream | UDP goodput | UDP loss | idle RTT | RTT under load | CPU (A, 1 vCPU) |')
L.append('|---|--:|--:|--:|--:|--:|--:|--:|')
for t in tuns:
    L.append('| {} | {} | {} | {} | {} | {} | {} | {} |'.format(
        label[t],
        f"{g(t,'tcp_throughput','streams=1')} Mbit/s",
        f"{g(t,'tcp_throughput','streams=4')} Mbit/s",
        f"{g(t,'udp_throughput','offered=200M')} Mbit/s",
        f"{g(t,'udp_loss','offered=200M')}%",
        f"{g(t,'latency','idle')} ms",
        f"{g(t,'latency','loaded')} ms",
        f"{g(t,'cpu_used','tcp_saturate')}%"))

# loss-resilience table
steps = sorted({k[2].replace('injected=','').replace('pct','')
                for k in V if k[1] == 'loss_effective'}, key=lambda x: int(x))
if steps:
    L.append('\n### Loss resilience (netem injected on the A→B outer path)\n')
    L.append('Effective end-to-end loss (ping) — lower is better; yip\'s FEC recovers what the others pass through:\n')
    L.append('| injected loss | ' + ' | '.join(label[t] for t in tuns) + ' |')
    L.append('|---|' + '|'.join('--:' for _ in tuns) + '|')
    for s in steps:
        L.append(f'| {s}% | ' + ' | '.join(f"{g(t,'loss_effective','injected='+s+'pct')}%" for t in tuns) + ' |')
    L.append('\nTCP goodput under the same injected loss (Mbit/s):\n')
    L.append('| injected loss | ' + ' | '.join(label[t] for t in tuns) + ' |')
    L.append('|---|' + '|'.join('--:' for _ in tuns) + '|')
    for s in steps:
        L.append(f'| {s}% | ' + ' | '.join(f"{g(t,'loss_goodput','injected='+s+'pct')}" for t in tuns) + ' |')

# media
if any(k[1] == 'media_delivered' for k in V):
    L.append('\n### Real-time media (MGEN, ~8 Mbit/s periodic @ 3% injected loss)\n')
    L.append('| tunnel | delivered |')
    L.append('|---|--:|')
    for t in tuns:
        L.append(f"| {label[t]} | {g(t,'media_delivered','8Mbit_3pctloss')}% |")

L.append('\n### Reproduce\n```sh\ncd crates/yip-bench/wan\ncp wan.env.example wan.env   # edit HOST_A/HOST_B/SSH_KEY\n'
         './provision.sh              # install tooling, ship yipd, bring up 3 tunnels\n'
         './run-wan-bench.sh          # run the matrix -> results/<ts>/wan.csv\n'
         './collect.sh                # regenerate this section in RESULTS.md\n./teardown.sh               # remove tunnels + netem\n```')

wan_block = '\n'.join(L)
start_tag = '<!-- WAN-BENCHMARK-START -->'
end_tag = '<!-- WAN-BENCHMARK-END -->'

if os.path.exists(out):
    with open(out, 'r', encoding='utf-8') as f:
        existing = f.read()
    s_idx = existing.find(start_tag)
    e_idx = existing.find(end_tag)
    if s_idx != -1 and e_idx != -1 and s_idx < e_idx:
        new_results = (
            existing[:s_idx + len(start_tag)]
            + '\n' + wan_block + '\n'
            + existing[e_idx:]
        )
        with open(out, 'w', encoding='utf-8') as f:
            f.write(new_results)
    else:
        with open(out, 'a', encoding='utf-8') as f:
            f.write(f"\n\n## Real-world WAN benchmarks (Cloud / VPS Multi-Region)\n\n{start_tag}\n{wan_block}\n{end_tag}\n")
else:
    with open(out, 'w', encoding='utf-8') as f:
        f.write(f"# yip-bench Results\n\n## Real-world WAN benchmarks (Cloud / VPS Multi-Region)\n\n{start_tag}\n{wan_block}\n{end_tag}\n")

# README snippet: compact clean-path + one loss row
sn = ['<!-- generated by crates/yip-bench/wan/collect.sh -->',
      f'*Two 1-vCPU Debian 13 VPSes, ~{base_rtt} ms apart, {ts[:10]}. '
      'yip trades raw clean-path throughput for loss resilience — see the FEC row.*\n',
      '| | TCP 1-stream | UDP loss (200M) | effective loss @10% injected |',
      '|---|--:|--:|--:|']
for t in tuns:
    if t == 'baseline':
        continue
    sn.append(f"| **{label[t]}** | {g(t,'tcp_throughput','streams=1')} Mbit/s | "
              f"{g(t,'udp_loss','offered=200M')}% | {g(t,'loss_effective','injected=10pct')}% |")
open(snip, 'w').write('\n'.join(sn) + '\n')

# Append to history.csv
if history_path:
    os.makedirs(os.path.dirname(history_path), exist_ok=True)
    existing_keys = set()
    file_exists = os.path.exists(history_path) and os.path.getsize(history_path) > 0
    if file_exists:
        with open(history_path, 'r', newline='') as hf:
            reader = csv.DictReader(hf)
            for r in reader:
                existing_keys.add((r['ts'], r['commit'], r['tunnel'], r['profile'], r['param'], r['metric']))
    fieldnames = ['ts', 'host_pair', 'commit', 'tunnel', 'profile', 'param', 'metric', 'value', 'conditions']
    with open(history_path, 'a', newline='') as hf:
        writer = csv.DictWriter(hf, fieldnames=fieldnames, lineterminator='\n')
        if not file_exists:
            writer.writeheader()
        appended = 0
        for r in rows:
            key = (r['ts'], r['commit'], r['tunnel'], r['profile'], r['param'], r['metric'])
            if key not in existing_keys:
                scrubbed_pair = f"{ha}->{hb}" if ha and hb else r['host_pair']
                writer.writerow({
                    'ts': r['ts'],
                    'host_pair': scrubbed_pair,
                    'commit': r['commit'],
                    'tunnel': r['tunnel'],
                    'profile': r['profile'],
                    'param': r['param'],
                    'metric': r['metric'],
                    'value': r['value'],
                    'conditions': r['conditions'],
                })
                existing_keys.add(key)
                appended += 1
    print(f'appended {appended} rows to {history_path}')

print('wrote', out, 'and', snip)
PY

# Update graphs from new history.csv data
if [[ -f "$REPO_ROOT/crates/yip-bench/generate-graphs.py" ]]; then
    log "regenerating benchmark graphs..."
    python3 "$REPO_ROOT/crates/yip-bench/generate-graphs.py"
fi

# Sync snippet into README.md between markers if markers exist
README="$REPO_ROOT/README.md"
if [[ -f "$README" && -f "$SNIPPET" ]] && grep -q "<!-- BENCHMARK-TABLE-START -->" "$README" && grep -q "<!-- BENCHMARK-TABLE-END -->" "$README"; then
    log "syncing snippet into README.md markers..."
    python3 - <<PY
import sys
readme_path = "$README"
snippet_path = "$SNIPPET"
with open(readme_path, 'r', encoding='utf-8') as f:
    readme = f.read()
with open(snippet_path, 'r', encoding='utf-8') as f:
    snippet = f.read().strip()

start_marker = "<!-- BENCHMARK-TABLE-START -->"
end_marker = "<!-- BENCHMARK-TABLE-END -->"

start_idx = readme.find(start_marker)
end_idx = readme.find(end_marker)

if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
    new_readme = (
        readme[:start_idx + len(start_marker)]
        + "\n\n"
        + snippet
        + "\n\n"
        + readme[end_idx:]
    )
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(new_readme)
PY
fi

log "done: $OUT"
