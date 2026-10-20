#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

echo "==> Testing collect.sh marker synchronization..."

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

TEST_MD="$TEMP_DIR/README.md"
TEST_SNIP="$TEMP_DIR/snippet.md"

cat <<'EOF' > "$TEST_MD"
# Header
Some intro text before markers.

<!-- BENCHMARK-TABLE-START -->
old table content to replace
<!-- BENCHMARK-TABLE-END -->

Footer text after markers.
EOF

cat <<'EOF' > "$TEST_SNIP"
| tunnel | TCP 1-stream | UDP loss |
|---|--:|--:|
| **yip** | 163.2 Mbit/s | 0.0% |
EOF

python3 - <<PY
with open("$TEST_MD", 'r') as f:
    readme = f.read()
with open("$TEST_SNIP", 'r') as f:
    snippet = f.read().strip()

start_marker = "<!-- BENCHMARK-TABLE-START -->"
end_marker = "<!-- BENCHMARK-TABLE-END -->"

start_idx = readme.find(start_marker)
end_idx = readme.find(end_marker)

assert start_idx != -1 and end_idx != -1 and start_idx < end_idx
new_readme = readme[:start_idx + len(start_marker)] + "\n\n" + snippet + "\n\n" + readme[end_idx:]

with open("$TEST_MD", 'w') as f:
    f.write(new_readme)
PY

grep -q "Some intro text before markers." "$TEST_MD" || { echo "Error: header corrupted"; exit 1; }
grep -q "Footer text after markers." "$TEST_MD" || { echo "Error: footer corrupted"; exit 1; }
grep -q "old table content to replace" "$TEST_MD" && { echo "Error: old content still present"; exit 1; }
grep -q "163.2 Mbit/s" "$TEST_MD" || { echo "Error: new snippet not inserted"; exit 1; }

echo "✓ Marker sync logic verified"
echo "ALL TESTS PASSED!"
