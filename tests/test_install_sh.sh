#!/bin/sh
# Automated integration test suite for install.sh
# Tests sandbox installation, checksum verification, and init system handling.

set -eu
(set -o pipefail 2>/dev/null) && set -o pipefail || true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_SH="$REPO_ROOT/install.sh"

if [ ! -f "$INSTALL_SH" ]; then
    echo "Error: install.sh not found at $INSTALL_SH" >&2
    exit 1
fi

# Sandbox working directory
TEST_ROOT="$(mktemp -d /tmp/yip-test-install-XXXXXX)"
cleanup() {
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

# Colors for test reporting
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

pass() {
    printf "%b[PASS]%b %s\n" "${GREEN}" "${NC}" "$1"
}

fail() {
    printf "%b[FAIL]%b %s\n" "${RED}" "${NC}" "$1" >&2
    exit 1
}

# Determine host target triple
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        TARGET="x86_64-unknown-linux-musl"
        ;;
    aarch64|arm64)
        TARGET="aarch64-unknown-linux-musl"
        ;;
    *)
        TARGET="x86_64-unknown-linux-musl"
        ;;
esac

VERSION="0.1.0"
TARBALL_NAME="yip-v${VERSION}-${TARGET}.tar.gz"
MOCK_DIR="$TEST_ROOT/mock_release"
STAGE_DIR="$MOCK_DIR/yip-v${VERSION}-${TARGET}"

echo "=== Preparing Mock Release Artifacts ==="
mkdir -p "$STAGE_DIR/contrib/systemd"
mkdir -p "$STAGE_DIR/contrib/openrc"
mkdir -p "$STAGE_DIR/contrib/runit/yipd/log"
mkdir -p "$STAGE_DIR/contrib/runit/yip-rendezvous/log"

# Mock binaries
cat <<'EOF' > "$STAGE_DIR/yipd"
#!/bin/sh
echo "yipd mock v0.1.0"
EOF

cat <<'EOF' > "$STAGE_DIR/yip-ca"
#!/bin/sh
echo "yip-ca mock v0.1.0"
EOF

cat <<'EOF' > "$STAGE_DIR/yip-rendezvous"
#!/bin/sh
echo "yip-rendezvous mock v0.1.0"
EOF

chmod 0755 "$STAGE_DIR/yipd" "$STAGE_DIR/yip-ca" "$STAGE_DIR/yip-rendezvous"

# Mock example.config
cat <<'EOF' > "$STAGE_DIR/example.config"
listen=0.0.0.0
device=yip0
EOF

# Mock contrib units
echo "[Unit]" > "$STAGE_DIR/contrib/systemd/yipd.service"
echo "[Unit]" > "$STAGE_DIR/contrib/systemd/yip-rendezvous.service"
echo "#!/sbin/openrc-run" > "$STAGE_DIR/contrib/openrc/yipd"
chmod 0755 "$STAGE_DIR/contrib/openrc/yipd"
echo "#!/sbin/openrc-run" > "$STAGE_DIR/contrib/openrc/yip-rendezvous"
chmod 0755 "$STAGE_DIR/contrib/openrc/yip-rendezvous"
echo "#!/bin/sh" > "$STAGE_DIR/contrib/runit/yipd/run"
chmod 0755 "$STAGE_DIR/contrib/runit/yipd/run"
echo "#!/bin/sh" > "$STAGE_DIR/contrib/runit/yipd/log/run"
chmod 0755 "$STAGE_DIR/contrib/runit/yipd/log/run"
echo "#!/bin/sh" > "$STAGE_DIR/contrib/runit/yip-rendezvous/run"
chmod 0755 "$STAGE_DIR/contrib/runit/yip-rendezvous/run"
echo "#!/bin/sh" > "$STAGE_DIR/contrib/runit/yip-rendezvous/log/run"
chmod 0755 "$STAGE_DIR/contrib/runit/yip-rendezvous/log/run"

# Package tarball
tar -czf "$MOCK_DIR/$TARBALL_NAME" -C "$MOCK_DIR" "yip-v${VERSION}-${TARGET}"

# Generate real SHA256SUMS
(cd "$MOCK_DIR" && sha256sum "$TARBALL_NAME" > "SHA256SUMS")

MOCK_TARBALL="$MOCK_DIR/$TARBALL_NAME"
MOCK_SHA256SUMS="$MOCK_DIR/SHA256SUMS"

echo "Mock tarball:    $MOCK_TARBALL"
echo "Mock SHA256SUMS: $MOCK_SHA256SUMS"
cat "$MOCK_SHA256SUMS"
echo ""

# -----------------------------------------------------------------------------
# Test Case 1: Valid install into sandbox paths (systemd)
# -----------------------------------------------------------------------------
echo "=== Test Case 1: Valid install into sandbox paths ==="
SB1="$TEST_ROOT/sandbox_1"
mkdir -p "$SB1"

OUTPUT_1=$(BINDIR="$SB1/bin" \
CONFDIR="$SB1/etc/yip" \
SYSD_DIR="$SB1/etc/systemd/system" \
LOCAL_TARBALL="$MOCK_TARBALL" \
LOCAL_SHA256SUMS="$MOCK_SHA256SUMS" \
INIT_SYSTEM="systemd" \
sh "$INSTALL_SH" 2>&1)

# Check binaries
[ -f "$SB1/bin/yipd" ] || fail "yipd binary not installed"
[ -x "$SB1/bin/yipd" ] || fail "yipd binary is not executable"
[ -f "$SB1/bin/yip-ca" ] || fail "yip-ca binary not installed"
[ -x "$SB1/bin/yip-ca" ] || fail "yip-ca binary is not executable"
[ -f "$SB1/bin/yip-rendezvous" ] || fail "yip-rendezvous binary not installed"
[ -x "$SB1/bin/yip-rendezvous" ] || fail "yip-rendezvous binary is not executable"

# Verify execution of installed binary
BIN_OUT=$("$SB1/bin/yipd")
case "$BIN_OUT" in
    *"yipd mock v0.1.0"*) ;;
    *) fail "yipd execution output unexpected: $BIN_OUT" ;;
esac

# Check config seeding
[ -f "$SB1/etc/yip/yipd.conf.example" ] || fail "yipd.conf.example not created"
grep -q "listen=0.0.0.0" "$SB1/etc/yip/yipd.conf.example" || fail "example config content mismatch"

# Check systemd service unit installation
[ -f "$SB1/etc/systemd/system/yipd.service" ] || fail "yipd.service not installed"
[ -f "$SB1/etc/systemd/system/yip-rendezvous.service" ] || fail "yip-rendezvous.service not installed"

pass "Test Case 1 passed: Binaries, permissions, config, and systemd units verified"

# -----------------------------------------------------------------------------
# Test Case 2: Corrupted tarball (SHA-256 verification failure)
# -----------------------------------------------------------------------------
echo "=== Test Case 2: Checksum mismatch rejection ==="
SB2="$TEST_ROOT/sandbox_2"
mkdir -p "$SB2"

CORRUPTED_TARBALL="$TEST_ROOT/corrupted-$TARBALL_NAME"
cp "$MOCK_TARBALL" "$CORRUPTED_TARBALL"
# Tamper with archive
echo "TAMPERED DATA" >> "$CORRUPTED_TARBALL"

set +e
OUTPUT_2=$(BINDIR="$SB2/bin" \
CONFDIR="$SB2/etc/yip" \
LOCAL_TARBALL="$CORRUPTED_TARBALL" \
LOCAL_SHA256SUMS="$MOCK_SHA256SUMS" \
INIT_SYSTEM="none" \
sh "$INSTALL_SH" 2>&1)
EXIT_CODE_2=$?
set -e

[ "$EXIT_CODE_2" -ne 0 ] || fail "install.sh succeeded on corrupted tarball (expected non-zero exit)"
case "$OUTPUT_2" in
    *"Checksum verification failed"*) ;;
    *) fail "Error output missing checksum failure notice: $OUTPUT_2" ;;
esac
[ ! -f "$SB2/bin/yipd" ] || fail "Binaries installed despite checksum mismatch"
[ ! -f "$SB2/etc/yip/yipd.conf.example" ] || fail "Config seeded despite checksum mismatch"

pass "Test Case 2 passed: Corrupted tarball was rejected before installation"

# -----------------------------------------------------------------------------
# Test Case 3: Explicit INIT_SYSTEM selection
# -----------------------------------------------------------------------------
echo "=== Test Case 3a: Explicit INIT_SYSTEM=openrc ==="
SB3A="$TEST_ROOT/sandbox_3a"
mkdir -p "$SB3A"

BINDIR="$SB3A/bin" \
CONFDIR="$SB3A/etc/yip" \
OPENRC_DIR="$SB3A/etc/init.d" \
SYSD_DIR="$SB3A/etc/systemd/system" \
LOCAL_TARBALL="$MOCK_TARBALL" \
LOCAL_SHA256SUMS="$MOCK_SHA256SUMS" \
INIT_SYSTEM="openrc" \
sh "$INSTALL_SH" >/dev/null 2>&1

[ -f "$SB3A/bin/yipd" ] || fail "binaries not installed"
[ -f "$SB3A/etc/init.d/yipd" ] || fail "OpenRC yipd service not installed"
[ -x "$SB3A/etc/init.d/yipd" ] || fail "OpenRC yipd service not executable"
[ -f "$SB3A/etc/init.d/yip-rendezvous" ] || fail "OpenRC yip-rendezvous service not installed"
[ -x "$SB3A/etc/init.d/yip-rendezvous" ] || fail "OpenRC yip-rendezvous service not executable"
[ ! -f "$SB3A/etc/systemd/system/yipd.service" ] || fail "systemd service installed when INIT_SYSTEM=openrc"

pass "Test Case 3a passed: OpenRC services correctly installed with executable permissions"

echo "=== Test Case 3b: Explicit INIT_SYSTEM=runit ==="
SB3B="$TEST_ROOT/sandbox_3b"
mkdir -p "$SB3B"

BINDIR="$SB3B/bin" \
CONFDIR="$SB3B/etc/yip" \
RUNIT_DIR="$SB3B/etc/sv" \
SYSD_DIR="$SB3B/etc/systemd/system" \
LOCAL_TARBALL="$MOCK_TARBALL" \
LOCAL_SHA256SUMS="$MOCK_SHA256SUMS" \
INIT_SYSTEM="runit" \
sh "$INSTALL_SH" >/dev/null 2>&1

[ -f "$SB3B/bin/yipd" ] || fail "binaries not installed"
[ -f "$SB3B/etc/sv/yipd/run" ] || fail "runit yipd run script not installed"
[ -x "$SB3B/etc/sv/yipd/run" ] || fail "runit yipd run script not executable"
[ -f "$SB3B/etc/sv/yipd/log/run" ] || fail "runit yipd log/run script not installed"
[ -x "$SB3B/etc/sv/yipd/log/run" ] || fail "runit yipd log/run script not executable"
[ -f "$SB3B/etc/sv/yip-rendezvous/run" ] || fail "runit yip-rendezvous run script not installed"
[ -x "$SB3B/etc/sv/yip-rendezvous/run" ] || fail "runit yip-rendezvous run script not executable"
[ ! -f "$SB3B/etc/systemd/system/yipd.service" ] || fail "systemd service installed when INIT_SYSTEM=runit"

pass "Test Case 3b passed: runit service directory and scripts installed"

echo "=== Test Case 3c: Explicit INIT_SYSTEM=none ==="
SB3C="$TEST_ROOT/sandbox_3c"
mkdir -p "$SB3C"

BINDIR="$SB3C/bin" \
CONFDIR="$SB3C/etc/yip" \
SYSD_DIR="$SB3C/etc/systemd/system" \
OPENRC_DIR="$SB3C/etc/init.d" \
RUNIT_DIR="$SB3C/etc/sv" \
LOCAL_TARBALL="$MOCK_TARBALL" \
LOCAL_SHA256SUMS="$MOCK_SHA256SUMS" \
INIT_SYSTEM="none" \
sh "$INSTALL_SH" >/dev/null 2>&1

[ -f "$SB3C/bin/yipd" ] || fail "binaries not installed"
[ -f "$SB3C/etc/yip/yipd.conf.example" ] || fail "example config not seeded"
[ ! -f "$SB3C/etc/systemd/system/yipd.service" ] || fail "systemd service installed when INIT_SYSTEM=none"
[ ! -f "$SB3C/etc/init.d/yipd" ] || fail "OpenRC service installed when INIT_SYSTEM=none"
[ ! -d "$SB3C/etc/sv/yipd" ] || fail "runit service installed when INIT_SYSTEM=none"

pass "Test Case 3c passed: INIT_SYSTEM=none skips service registration"

echo "=== Test Case 3d: Explicit INIT_SYSTEM=systemd ==="
SB3D="$TEST_ROOT/sandbox_3d"
mkdir -p "$SB3D"

BINDIR="$SB3D/bin" \
CONFDIR="$SB3D/etc/yip" \
SYSD_DIR="$SB3D/etc/systemd/system" \
LOCAL_TARBALL="$MOCK_TARBALL" \
LOCAL_SHA256SUMS="$MOCK_SHA256SUMS" \
INIT_SYSTEM="systemd" \
sh "$INSTALL_SH" >/dev/null 2>&1

[ -f "$SB3D/bin/yipd" ] || fail "binaries not installed"
[ -f "$SB3D/etc/systemd/system/yipd.service" ] || fail "systemd yipd.service missing"
[ -f "$SB3D/etc/systemd/system/yip-rendezvous.service" ] || fail "systemd yip-rendezvous.service missing"

pass "Test Case 3d passed: INIT_SYSTEM=systemd correctly installed units"

# -----------------------------------------------------------------------------
# Test Case 4: Invalid INIT_SYSTEM handling
# -----------------------------------------------------------------------------
echo "=== Test Case 4: Invalid INIT_SYSTEM handling ==="
SB4="$TEST_ROOT/sandbox_4"
mkdir -p "$SB4"

set +e
OUTPUT_4=$(BINDIR="$SB4/bin" \
CONFDIR="$SB4/etc/yip" \
LOCAL_TARBALL="$MOCK_TARBALL" \
LOCAL_SHA256SUMS="$MOCK_SHA256SUMS" \
INIT_SYSTEM="nonexistent_init" \
sh "$INSTALL_SH" 2>&1)
EXIT_CODE_4=$?
set -e

[ "$EXIT_CODE_4" -ne 0 ] || fail "install.sh succeeded with invalid INIT_SYSTEM"
case "$OUTPUT_4" in
    *"Unknown INIT_SYSTEM"*) ;;
    *) fail "Unexpected output for invalid INIT_SYSTEM: $OUTPUT_4" ;;
esac

pass "Test Case 4 passed: Unknown INIT_SYSTEM correctly rejected"

# -----------------------------------------------------------------------------
# Test Case 5: Architecture and Missing Binary Checks
# -----------------------------------------------------------------------------
echo "=== Test Case 5: Missing binary in archive detection ==="
SB5="$TEST_ROOT/sandbox_5"
mkdir -p "$SB5"

INCOMPLETE_DIR="$TEST_ROOT/incomplete_release"
mkdir -p "$INCOMPLETE_DIR/yip-v${VERSION}-${TARGET}"
# Only create yipd, omit yip-ca and yip-rendezvous
echo "#!/bin/sh" > "$INCOMPLETE_DIR/yip-v${VERSION}-${TARGET}/yipd"
chmod +x "$INCOMPLETE_DIR/yip-v${VERSION}-${TARGET}/yipd"
tar -czf "$INCOMPLETE_DIR/incomplete.tar.gz" -C "$INCOMPLETE_DIR" "yip-v${VERSION}-${TARGET}"

set +e
OUTPUT_5=$(BINDIR="$SB5/bin" \
CONFDIR="$SB5/etc/yip" \
LOCAL_TARBALL="$INCOMPLETE_DIR/incomplete.tar.gz" \
INIT_SYSTEM="none" \
sh "$INSTALL_SH" 2>&1)
EXIT_CODE_5=$?
set -e

[ "$EXIT_CODE_5" -ne 0 ] || fail "install.sh succeeded with missing required binaries"
case "$OUTPUT_5" in
    *"not found in release archive"*|*"missing from release archive"*) ;;
    *) fail "Unexpected output for missing binary: $OUTPUT_5" ;;
esac

pass "Test Case 5 passed: Incomplete archive with missing binaries detected and rejected"

echo ""
echo "=========================================="
printf "%bALL INSTALLER INTEGRATION TESTS PASSED!%b\n" "${GREEN}" "${NC}"
echo "=========================================="
