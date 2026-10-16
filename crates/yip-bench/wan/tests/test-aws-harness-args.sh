#!/usr/bin/env bash
# Unit and integration tests for AWS harness argument parsing, dry-run,
# graceful exit on missing state, and mocked AWS CLI orchestration.
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAN_DIR="$(cd "$TEST_DIR/.." && pwd)"

UP_SCRIPT="$WAN_DIR/aws-up.sh"
DOWN_SCRIPT="$WAN_DIR/aws-down.sh"

TMP_DIR="$(mktemp -d -t yip-wan-test-XXXXXX)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# ── test assertion helpers ───────────────────────────────────────────────────
PASSED=0
FAILED=0

test_start() {
    printf '\033[1;34m[TEST]\033[0m %s...\n' "$1"
}

assert_success() {
    local desc="$1"
    shift
    if "$@"; then
        printf '  \033[1;32m✓\033[0m %s\n' "$desc"
        PASSED=$((PASSED + 1))
    else
        printf '  \033[1;31m✗ FAIL:\033[0m %s\n' "$desc"
        FAILED=$((FAILED + 1))
    fi
}

assert_failure() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        printf '  \033[1;31m✗ FAIL (expected failure):\033[0m %s\n' "$desc"
        FAILED=$((FAILED + 1))
    else
        printf '  \033[1;32m✓\033[0m %s\n' "$desc"
        PASSED=$((PASSED + 1))
    fi
}

assert_contains() {
    local desc="$1"
    local needle="$2"
    local haystack="$3"
    if grep -qi -- "$needle" <<<"$haystack"; then
        printf '  \033[1;32m✓\033[0m %s\n' "$desc"
        PASSED=$((PASSED + 1))
    else
        printf '  \033[1;31m✗ FAIL (pattern "%s" not found):\033[0m %s\n' "$needle" "$desc"
        FAILED=$((FAILED + 1))
    fi
}

# ── 1. Help message checks ──────────────────────────────────────────────────
test_start "Help flags (--help and -h)"
out=$("$UP_SCRIPT" --help)
assert_contains "aws-up.sh --help outputs usage" "usage:" "$out"

out=$("$UP_SCRIPT" -h)
assert_contains "aws-up.sh -h outputs usage" "usage:" "$out"

out=$("$DOWN_SCRIPT" --help)
assert_contains "aws-down.sh --help outputs usage" "usage:" "$out"

out=$("$DOWN_SCRIPT" -h)
assert_contains "aws-down.sh -h outputs usage" "usage:" "$out"

# ── 2. Invalid option handling ──────────────────────────────────────────────
test_start "Invalid options rejected"
assert_failure "aws-up.sh rejects --nonexistent-option" "$UP_SCRIPT" --nonexistent-option
assert_failure "aws-up.sh rejects missing value for --region-a" "$UP_SCRIPT" --region-a
assert_failure "aws-down.sh rejects --nonexistent-option" "$DOWN_SCRIPT" --nonexistent-option

# ── 3. Graceful exit on missing state ────────────────────────────────────────
test_start "Graceful exit on missing state for aws-down.sh"
MISSING_SESSION="$TMP_DIR/nonexistent-session.json"
assert_success "aws-down.sh exits 0 on missing session file (positional)" "$DOWN_SCRIPT" "$MISSING_SESSION"
assert_success "aws-down.sh exits 0 on missing session file (--session)" "$DOWN_SCRIPT" --session "$MISSING_SESSION"

# ── 4. Dry-run default parameter verification ───────────────────────────────
test_start "Dry-run with default parameters"
DRY_SESSION="$TMP_DIR/dry_default_session.json"
DRY_ENV="$TMP_DIR/dry_default_wan.env"
DRY_KEY="$TMP_DIR/dry_default_key"

assert_success "aws-up.sh --dry-run completes successfully" \
    "$UP_SCRIPT" --dry-run \
                 --session-file "$DRY_SESSION" \
                 --env-file "$DRY_ENV" \
                 --key-file "$DRY_KEY"

assert_success "Dry-run created session file" test -f "$DRY_SESSION"
assert_success "Dry-run created env file" test -f "$DRY_ENV"
assert_success "Dry-run created private key" test -f "$DRY_KEY"

# Check default contents
assert_success "Default Region A is us-east-1 in session" grep -q '"region": "us-east-1"' "$DRY_SESSION"
assert_success "Default Region B is us-west-2 in session" grep -q '"region": "us-west-2"' "$DRY_SESSION"
assert_success "Default Instance Type is t3.small in session" grep -q '"instance_type": "t3.small"' "$DRY_SESSION"
assert_success "Default SSH user is admin in session" grep -q '"ssh_user": "admin"' "$DRY_SESSION"

assert_success "Default SSH user is admin in wan.env" grep -q 'SSH_USER=admin' "$DRY_ENV"
assert_success "Standard YIP_PORT=51833 in wan.env" grep -q 'YIP_PORT=51833' "$DRY_ENV"
assert_success "Standard WG_PORT=51834 in wan.env" grep -q 'WG_PORT=51834' "$DRY_ENV"
assert_success "Standard OVPN_PORT=51835 in wan.env" grep -q 'OVPN_PORT=51835' "$DRY_ENV"
assert_success "Standard OVERLAY_MTU=1380 in wan.env" grep -q 'OVERLAY_MTU=1380' "$DRY_ENV"

# ── 5. Dry-run custom CLI options verification ──────────────────────────────
test_start "Dry-run with custom CLI arguments"
CUSTOM_SESSION="$TMP_DIR/custom_session.json"
CUSTOM_ENV="$TMP_DIR/custom_wan.env"
CUSTOM_KEY="$TMP_DIR/custom_key"

assert_success "aws-up.sh --dry-run with custom flags" \
    "$UP_SCRIPT" --dry-run \
                 --region-a "eu-central-1" \
                 --region-b "ap-northeast-1" \
                 --instance-type "c6i.large" \
                 --ssh-user "ubuntu" \
                 --session-file "$CUSTOM_SESSION" \
                 --env-file "$CUSTOM_ENV" \
                 --key-file "$CUSTOM_KEY"

assert_success "Custom Region A eu-central-1 in session" grep -q '"region": "eu-central-1"' "$CUSTOM_SESSION"
assert_success "Custom Region B ap-northeast-1 in session" grep -q '"region": "ap-northeast-1"' "$CUSTOM_SESSION"
assert_success "Custom Instance Type c6i.large in session" grep -q '"instance_type": "c6i.large"' "$CUSTOM_SESSION"
assert_success "Custom SSH user ubuntu in session" grep -q '"ssh_user": "ubuntu"' "$CUSTOM_SESSION"
assert_success "Custom SSH user ubuntu in wan.env" grep -q 'SSH_USER=ubuntu' "$CUSTOM_ENV"
assert_success "Custom region label A in wan.env" grep -q 'HOST_A_LABEL="EC2 eu-central-1 (c6i.large)"' "$CUSTOM_ENV"
assert_success "Custom region label B in wan.env" grep -q 'HOST_B_LABEL="EC2 ap-northeast-1 (c6i.large)"' "$CUSTOM_ENV"

# ── 6. Environment variable overrides ───────────────────────────────────────
test_start "Environment variable overrides"
ENV_SESSION="$TMP_DIR/env_session.json"
ENV_ENV="$TMP_DIR/env_wan.env"
ENV_KEY="$TMP_DIR/env_key"

assert_success "aws-up.sh respects AWS_REGION_A/B and AWS_INSTANCE_TYPE" \
    env AWS_REGION_A="sa-east-1" \
        AWS_REGION_B="ca-central-1" \
        AWS_INSTANCE_TYPE="t4g.small" \
        SSH_USER="root" \
        "$UP_SCRIPT" --dry-run \
                     --session-file "$ENV_SESSION" \
                     --env-file "$ENV_ENV" \
                     --key-file "$ENV_KEY"

assert_success "Env var Region A sa-east-1 in session" grep -q '"region": "sa-east-1"' "$ENV_SESSION"
assert_success "Env var Region B ca-central-1 in session" grep -q '"region": "ca-central-1"' "$ENV_SESSION"
assert_success "Env var Instance Type t4g.small in session" grep -q '"instance_type": "t4g.small"' "$ENV_SESSION"
assert_success "Env var SSH user root in session" grep -q '"ssh_user": "root"' "$ENV_SESSION"

# ── 7. Dry-run teardown with aws-down.sh ────────────────────────────────────
test_start "Dry-run teardown with aws-down.sh"
assert_success "aws-down.sh --dry-run removes mock session and key files" \
    "$DOWN_SCRIPT" --dry-run --session "$CUSTOM_SESSION"
assert_success "Session file was cleaned up" test ! -f "$CUSTOM_SESSION"
assert_success "Private key file was cleaned up" test ! -f "$CUSTOM_KEY"
assert_success "Public key file was cleaned up" test ! -f "$CUSTOM_KEY.pub"

# ── 8. Integration test with mocked AWS CLI ─────────────────────────────────
test_start "Mocked AWS CLI full lifecycle integration"
MOCK_BIN_DIR="$TMP_DIR/mock_bin"
mkdir -p "$MOCK_BIN_DIR"
MOCK_LOG="$TMP_DIR/mock_aws.log"

cat <<'EOF' > "$MOCK_BIN_DIR/aws"
#!/usr/bin/env bash
echo "aws $*" >> "${MOCK_LOG_FILE}"

case "$*" in
    *"ec2 describe-images"*)
        echo "ami-0123456789mockami"
        ;;
    *"ec2 import-key-pair"*)
        echo '{"KeyName": "mock-key"}'
        ;;
    *"ec2 create-security-group"*)
        echo "sg-0123456789mocksg"
        ;;
    *"ec2 authorize-security-group-ingress"*)
        echo '{"Return": true}'
        ;;
    *"ec2 run-instances"*)
        echo "i-0123456789mockinst"
        ;;
    *"ec2 wait instance-running"*)
        exit 0
        ;;
    *"ec2 describe-instances"*)
        echo "203.0.113.88"
        ;;
    *"ec2 terminate-instances"*)
        echo '{"TerminatingInstances": []}'
        ;;
    *"ec2 wait instance-terminated"*)
        exit 0
        ;;
    *"ec2 delete-security-group"*)
        exit 0
        ;;
    *"ec2 delete-key-pair"*)
        exit 0
        ;;
    *)
        echo "MOCK_AWS: unhandled command $*" >&2
        exit 0
        ;;
esac
EOF
chmod +x "$MOCK_BIN_DIR/aws"

MOCK_SESSION="$TMP_DIR/mock_live_session.json"
MOCK_ENV="$TMP_DIR/mock_live_wan.env"
MOCK_KEY="$TMP_DIR/mock_live_key"

assert_success "aws-up.sh runs against mocked AWS CLI" \
    env PATH="$MOCK_BIN_DIR:$PATH" MOCK_LOG_FILE="$MOCK_LOG" \
    "$UP_SCRIPT" --skip-ssh-wait \
                 --session-file "$MOCK_SESSION" \
                 --env-file "$MOCK_ENV" \
                 --key-file "$MOCK_KEY"

assert_success "Mock session file created" test -f "$MOCK_SESSION"
assert_success "Mock env file created" test -f "$MOCK_ENV"
assert_success "Mock key created" test -f "$MOCK_KEY"
assert_success "Recorded ec2 describe-images call" grep -q "ec2 describe-images" "$MOCK_LOG"
assert_success "Recorded ec2 import-key-pair call" grep -q "ec2 import-key-pair" "$MOCK_LOG"
assert_success "Recorded ec2 create-security-group call" grep -q "ec2 create-security-group" "$MOCK_LOG"
assert_success "Recorded ec2 authorize-security-group-ingress call" grep -q "ec2 authorize-security-group-ingress" "$MOCK_LOG"
assert_success "Recorded ec2 run-instances call" grep -q "ec2 run-instances" "$MOCK_LOG"
assert_success "Recorded ec2 wait instance-running call" grep -q "ec2 wait instance-running" "$MOCK_LOG"

assert_success "aws-down.sh executes against mocked AWS CLI" \
    env PATH="$MOCK_BIN_DIR:$PATH" MOCK_LOG_FILE="$MOCK_LOG" \
    "$DOWN_SCRIPT" --session "$MOCK_SESSION"

assert_success "Recorded ec2 terminate-instances call" grep -q "ec2 terminate-instances" "$MOCK_LOG"
assert_success "Recorded ec2 wait instance-terminated call" grep -q "ec2 wait instance-terminated" "$MOCK_LOG"
assert_success "Recorded ec2 delete-security-group call" grep -q "ec2 delete-security-group" "$MOCK_LOG"
assert_success "Recorded ec2 delete-key-pair call" grep -q "ec2 delete-key-pair" "$MOCK_LOG"
assert_success "Mock session file removed by aws-down.sh" test ! -f "$MOCK_SESSION"
assert_success "Mock key file removed by aws-down.sh" test ! -f "$MOCK_KEY"

# ── Summary ─────────────────────────────────────────────────────────────────
printf '\n\033[1;35m════════════════════════════════════════════════════\033[0m\n'
printf 'Tests Passed: %d\n' "$PASSED"
printf 'Tests Failed: %d\n' "$FAILED"
printf '\033[1;35m════════════════════════════════════════════════════\033[0m\n'

if (( FAILED > 0 )); then
    exit 1
fi
exit 0
