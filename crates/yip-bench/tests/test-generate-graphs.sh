#!/usr/bin/env bash
set -euo pipefail

# Find repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
cd "${REPO_ROOT}"

echo "==> Testing generate-graphs.py..."

# 1. Run generation script
python3 crates/yip-bench/generate-graphs.py

# 2. Verify all three SVGs were generated
SVGS=(
    "assets/bench-throughput-loss.svg"
    "assets/bench-fec-recovery.svg"
    "assets/bench-multicore-scaling.svg"
)

for svg in "${SVGS[@]}"; do
    if [[ ! -f "$svg" ]]; then
        echo "FAIL: Expected $svg to exist"
        exit 1
    fi
    echo "✓ Found $svg"
done

# 3. Verify all SVGs parse as valid XML
python3 -c "
import xml.etree.ElementTree as ET
import sys

for path in ['assets/bench-throughput-loss.svg', 'assets/bench-fec-recovery.svg', 'assets/bench-multicore-scaling.svg']:
    try:
        ET.parse(path)
        print(f'✓ Valid XML: {path}')
    except Exception as e:
        print(f'FAIL: Invalid XML {path}: {e}', file=sys.stderr)
        sys.exit(1)
"

# 4. Verify SVG card styling: rx="12" and stroke="#30363d"
for svg in "${SVGS[@]}"; do
    if ! grep -q 'rx="12"' "$svg"; then
        echo "FAIL: $svg missing rx=\"12\" card rounded corner"
        exit 1
    fi
    if ! grep -q 'stroke="#30363d"' "$svg"; then
        echo "FAIL: $svg missing stroke=\"#30363d\" card border"
        exit 1
    fi
    echo "✓ Card styling verified: $svg"
done

# 5. Verify determinism: running twice produces identical sha256 sums
HASH_BEFORE_1=$(sha256sum "assets/bench-throughput-loss.svg" | awk '{print $1}')
HASH_BEFORE_2=$(sha256sum "assets/bench-fec-recovery.svg" | awk '{print $1}')
HASH_BEFORE_3=$(sha256sum "assets/bench-multicore-scaling.svg" | awk '{print $1}')

python3 crates/yip-bench/generate-graphs.py

HASH_AFTER_1=$(sha256sum "assets/bench-throughput-loss.svg" | awk '{print $1}')
HASH_AFTER_2=$(sha256sum "assets/bench-fec-recovery.svg" | awk '{print $1}')
HASH_AFTER_3=$(sha256sum "assets/bench-multicore-scaling.svg" | awk '{print $1}')

if [[ "$HASH_BEFORE_1" != "$HASH_AFTER_1" || "$HASH_BEFORE_2" != "$HASH_AFTER_2" || "$HASH_BEFORE_3" != "$HASH_AFTER_3" ]]; then
    echo "FAIL: Non-deterministic output detected between runs!"
    exit 1
fi
echo "✓ Determinism verified (sha256 unchanged across re-runs)"

# 6. Verify --check mode behavior
# 6a. Clean check should succeed (exit 0)
python3 crates/yip-bench/generate-graphs.py --check
echo "✓ --check passed on clean state"

# 6b. Modified asset should cause --check to fail (exit 1)
TMP_BACKUP=$(mktemp)
cp assets/bench-throughput-loss.svg "$TMP_BACKUP"
echo "<!-- drift -->" >> assets/bench-throughput-loss.svg

if python3 crates/yip-bench/generate-graphs.py --check; then
    echo "FAIL: --check should have failed on drifted asset"
    cp "$TMP_BACKUP" assets/bench-throughput-loss.svg
    rm -f "$TMP_BACKUP"
    exit 1
fi
echo "✓ --check correctly failed on drifted asset"
cp "$TMP_BACKUP" assets/bench-throughput-loss.svg
rm -f "$TMP_BACKUP"

# 6c. Missing asset should cause --check to fail (exit 1)
TMP_BACKUP=$(mktemp)
mv assets/bench-fec-recovery.svg "$TMP_BACKUP"

if python3 crates/yip-bench/generate-graphs.py --check; then
    echo "FAIL: --check should have failed on missing asset"
    mv "$TMP_BACKUP" assets/bench-fec-recovery.svg
    rm -f "$TMP_BACKUP"
    exit 1
fi
echo "✓ --check correctly failed on missing asset"
mv "$TMP_BACKUP" assets/bench-fec-recovery.svg
rm -f "$TMP_BACKUP"

# Final check that clean --check passes
python3 crates/yip-bench/generate-graphs.py --check
echo "ALL TESTS PASSED!"
