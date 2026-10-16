#!/usr/bin/env bash
# Tear down ephemeral EC2 instances, security groups, and keypairs created
# by aws-up.sh. Safe, idempotent, and failsafe: exit 0 if resources do not exist.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── logging ─────────────────────────────────────────────────────────────────
log()  { printf '\033[1;36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
warn() { printf '\033[1;33m[%s] WARN:\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '\033[1;31m[%s] FATAL:\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

# ── defaults ────────────────────────────────────────────────────────────────
SESSION_FILE="${SESSION_FILE:-$SCRIPT_DIR/results/.aws-session.json}"
DRY_RUN=0

show_help() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [SESSION_FILE]

Tear down ephemeral EC2 resources created by aws-up.sh.

Arguments:
  SESSION_FILE              Path to .aws-session.json (default: results/.aws-session.json)

Options:
  --session-file <path>     Explicit path to session JSON file
  --dry-run                 Simulate teardown without deleting cloud resources
  -h, --help                Show this help message and exit
EOF
}

# ── argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --session-file|--session)
            [[ -n "${2:-}" ]] || die "--session-file requires an argument"
            SESSION_FILE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            if [[ "$1" =~ ^- ]]; then
                die "unknown option: $1 (use --help for options)"
            else
                SESSION_FILE="$1"
                shift
            fi
            ;;
    esac
done

if [[ ! -f "$SESSION_FILE" ]]; then
    log "no session file found at $SESSION_FILE; nothing to tear down."
    # Clean up local key files if present
    rm -f "$SCRIPT_DIR/id_ed25519_wan" "$SCRIPT_DIR/id_ed25519_wan.pub" 2>/dev/null || true
    exit 0
fi

log "reading session state from $SESSION_FILE"

# ── parse session json ──────────────────────────────────────────────────────
# Safe parsing via python3
read_meta() {
    python3 -c "
import sys, json
try:
    with open('$SESSION_FILE', 'r') as f:
        d = json.load(f)
    print(d.get('key_name', ''))
    print(d.get('key_file', ''))
    print(d.get('region_a', {}).get('region', ''))
    print(d.get('region_a', {}).get('instance_id', ''))
    print(d.get('region_a', {}).get('security_group_id', ''))
    print(d.get('region_b', {}).get('region', ''))
    print(d.get('region_b', {}).get('instance_id', ''))
    print(d.get('region_b', {}).get('security_group_id', ''))
except Exception as e:
    sys.stderr.write(f'JSON parse error: {e}\n')
    sys.exit(1)
"
}

METADATA=()
while IFS= read -r line; do
    METADATA+=("$line")
done < <(read_meta)

KEY_NAME="${METADATA[0]:-}"
KEY_FILE="${METADATA[1]:-}"
REGION_A="${METADATA[2]:-}"
INST_A="${METADATA[3]:-}"
SG_A="${METADATA[4]:-}"
REGION_B="${METADATA[5]:-}"
INST_B="${METADATA[6]:-}"
SG_B="${METADATA[7]:-}"

log "session details:"
log "  Key Name:   $KEY_NAME"
log "  Region A:   $REGION_A (Instance: $INST_A, SG: $SG_A)"
log "  Region B:   $REGION_B (Instance: $INST_B, SG: $SG_B)"
if [[ "$DRY_RUN" == "1" ]]; then
    log "mode:         DRY RUN"
fi

if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run: would terminate instance $INST_A in $REGION_A"
    log "dry-run: would terminate instance $INST_B in $REGION_B"
    log "dry-run: would delete security group $SG_A in $REGION_A"
    log "dry-run: would delete security group $SG_B in $REGION_B"
    log "dry-run: would delete keypair $KEY_NAME in $REGION_A and $REGION_B"
    log "dry-run: would remove key files and session file"
    # In dry-run, remove session file and keys if they were created during tests
    if [[ -n "$KEY_FILE" && -f "$KEY_FILE" ]]; then
        rm -f "$KEY_FILE" "${KEY_FILE}.pub" 2>/dev/null || true
    fi
    rm -f "$SCRIPT_DIR/id_ed25519_wan" "$SCRIPT_DIR/id_ed25519_wan.pub" "$SESSION_FILE" 2>/dev/null || true
    log "dry-run teardown complete."
    exit 0
fi

# ── terminate instances ─────────────────────────────────────────────────────
if [[ -n "$INST_A" && -n "$REGION_A" ]]; then
    log "terminating instance $INST_A in $REGION_A..."
    aws ec2 terminate-instances --region "$REGION_A" --instance-ids "$INST_A" >/dev/null 2>&1 || true
fi

if [[ -n "$INST_B" && -n "$REGION_B" ]]; then
    log "terminating instance $INST_B in $REGION_B..."
    aws ec2 terminate-instances --region "$REGION_B" --instance-ids "$INST_B" >/dev/null 2>&1 || true
fi

# ── wait for instances to be terminated ─────────────────────────────────────
if [[ -n "$INST_A" && -n "$REGION_A" ]]; then
    log "waiting for instance $INST_A to terminate..."
    aws ec2 wait instance-terminated --region "$REGION_A" --instance-ids "$INST_A" >/dev/null 2>&1 || true
fi

if [[ -n "$INST_B" && -n "$REGION_B" ]]; then
    log "waiting for instance $INST_B to terminate..."
    aws ec2 wait instance-terminated --region "$REGION_B" --instance-ids "$INST_B" >/dev/null 2>&1 || true
fi

# ── delete security groups (with retry for ENI release) ─────────────────────
delete_security_group() {
    local region="$1"
    local sg="$2"
    [[ -n "$region" && -n "$sg" ]] || return 0

    log "deleting security group $sg in $region..."
    local deadline=$((SECONDS + 45))
    while (( SECONDS < deadline )); do
        local out err=0
        out=$(aws ec2 delete-security-group --region "$region" --group-id "$sg" 2>&1) || err=$?
        if (( err == 0 )) || grep -qi "InvalidGroup.NotFound" <<<"$out"; then
            return 0
        fi
        sleep 4
    done
    warn "could not delete security group $sg in $region (may require manual removal): $out"
}

delete_security_group "$REGION_A" "$SG_A"
delete_security_group "$REGION_B" "$SG_B"

# ── delete keypairs ─────────────────────────────────────────────────────────
if [[ -n "$KEY_NAME" ]]; then
    if [[ -n "$REGION_A" ]]; then
        log "deleting keypair $KEY_NAME in $REGION_A..."
        aws ec2 delete-key-pair --region "$REGION_A" --key-name "$KEY_NAME" >/dev/null 2>&1 || true
    fi
    if [[ -n "$REGION_B" ]]; then
        log "deleting keypair $KEY_NAME in $REGION_B..."
        aws ec2 delete-key-pair --region "$REGION_B" --key-name "$KEY_NAME" >/dev/null 2>&1 || true
    fi
fi

# ── remove local credentials and session file ───────────────────────────────
log "cleaning up local key files and session file..."
if [[ -n "$KEY_FILE" ]]; then
    rm -f "$KEY_FILE" "${KEY_FILE}.pub" 2>/dev/null || true
fi
rm -f "$SCRIPT_DIR/id_ed25519_wan" "$SCRIPT_DIR/id_ed25519_wan.pub" "$SESSION_FILE" 2>/dev/null || true

log "teardown complete. All ephemeral resources deleted."
exit 0
