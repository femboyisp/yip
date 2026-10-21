#!/usr/bin/env bash
set -euo pipefail

# Find repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
cd "${REPO_ROOT}"

echo "==> Testing generate-wire-format.py..."

# 1. Run generation script
python3 crates/yip-bench/generate-wire-format.py

# 2. Verify wire-format.svg exists
SVG="assets/wire-format.svg"
if [[ ! -f "$SVG" ]]; then
    echo "FAIL: Expected $SVG to exist"
    exit 1
fi
echo "✓ Found $SVG"

# 3. Verify SVG parses as valid XML
python3 -c "
import xml.etree.ElementTree as ET
import sys

try:
    ET.parse('assets/wire-format.svg')
    print('✓ Valid XML: assets/wire-format.svg')
except Exception as e:
    print(f'FAIL: Invalid XML in assets/wire-format.svg: {e}', file=sys.stderr)
    sys.exit(1)
"

# 4. Verify SVG dimensions and card styling: 1040x820, rx="8", stroke="#30363d"
if ! grep -q 'viewBox="0 0 1040 820"' "$SVG"; then
    echo "FAIL: $SVG missing viewBox=\"0 0 1040 820\""
    exit 1
fi
if ! grep -q 'rx="8.00"' "$SVG"; then
    echo "FAIL: $SVG missing rx=\"8.00\" panel rounded corner"
    exit 1
fi
if ! grep -q 'stroke="#30363d"' "$SVG"; then
    echo "FAIL: $SVG missing stroke=\"#30363d\" border"
    exit 1
fi
echo "✓ Card styling and dimensions verified: $SVG"

# 5. Verify determinism: running twice produces identical sha256 sums
HASH_BEFORE=$(sha256sum "$SVG" | awk '{print $1}')
python3 crates/yip-bench/generate-wire-format.py
HASH_AFTER=$(sha256sum "$SVG" | awk '{print $1}')

if [[ "$HASH_BEFORE" != "$HASH_AFTER" ]]; then
    echo "FAIL: Non-deterministic output detected between runs!"
    exit 1
fi
echo "✓ Determinism verified (sha256 unchanged across re-runs: $HASH_BEFORE)"

# 6. Verify --check mode behavior
# 6a. Clean check should succeed (exit 0)
python3 crates/yip-bench/generate-wire-format.py --check
echo "✓ --check passed on clean state"

# 6b. Modified asset should cause --check to fail (exit 1)
TMP_BACKUP=$(mktemp)
cp "$SVG" "$TMP_BACKUP"
echo "<!-- drift -->" >> "$SVG"

if python3 crates/yip-bench/generate-wire-format.py --check; then
    echo "FAIL: --check should have failed on drifted asset"
    cp "$TMP_BACKUP" "$SVG"
    rm -f "$TMP_BACKUP"
    exit 1
fi
echo "✓ --check correctly failed on drifted asset"
cp "$TMP_BACKUP" "$SVG"
rm -f "$TMP_BACKUP"

# 6c. Missing asset should cause --check to fail (exit 1)
TMP_BACKUP=$(mktemp)
mv "$SVG" "$TMP_BACKUP"

if python3 crates/yip-bench/generate-wire-format.py --check; then
    echo "FAIL: --check should have failed on missing asset"
    mv "$TMP_BACKUP" "$SVG"
    exit 1
fi
echo "✓ --check correctly failed on missing asset"
mv "$TMP_BACKUP" "$SVG"

echo "==> All generate-wire-format tests passed!"
