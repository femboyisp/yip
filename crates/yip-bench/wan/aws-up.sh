#!/usr/bin/env bash
# Spin up two ephemeral EC2 instances across configurable AWS regions,
# configure security groups, create and import temporary keypairs,
# and write wan.env and results/.aws-session.json for the WAN benchmark suite.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# ── logging ─────────────────────────────────────────────────────────────────
log()  { printf '\033[1;36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
warn() { printf '\033[1;33m[%s] WARN:\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '\033[1;31m[%s] FATAL:\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

# ── defaults ────────────────────────────────────────────────────────────────
REGION_A="${AWS_REGION_A:-us-east-1}"
REGION_B="${AWS_REGION_B:-us-west-2}"
INSTANCE_TYPE="${AWS_INSTANCE_TYPE:-t3.small}"
SSH_USER="${SSH_USER:-admin}"
AMI_A="${AWS_AMI_A:-}"
AMI_B="${AWS_AMI_B:-}"
KEY_FILE="${KEY_FILE:-$SCRIPT_DIR/id_ed25519_wan}"
SESSION_FILE="${SESSION_FILE:-$SCRIPT_DIR/results/.aws-session.json}"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/wan.env}"
DRY_RUN=0
SKIP_SSH_WAIT=0

show_help() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Spin up two ephemeral EC2 instances across two AWS regions for WAN benchmarks.

Options:
  --region-a <region>       AWS Region for Host A (default: \${AWS_REGION_A:-us-east-1})
  --region-b <region>       AWS Region for Host B (default: \${AWS_REGION_B:-us-west-2})
  --instance-type <type>    EC2 instance type (default: \${AWS_INSTANCE_TYPE:-t3.small})
  --ssh-user <user>         SSH username (default: \${SSH_USER:-admin})
  --ami-a <ami-id>          Override AMI ID for Region A (auto-detects Debian 12 if unset)
  --ami-b <ami-id>          Override AMI ID for Region B (auto-detects Debian 12 if unset)
  --key-file <path>         Path to write temporary private key (default: id_ed25519_wan)
  --session-file <path>     Path for session JSON (default: results/.aws-session.json)
  --env-file <path>         Path to write output env (default: wan.env)
  --dry-run                 Simulate deployment without creating cloud resources
  --skip-ssh-wait           Skip waiting for SSH connectivity
  -h, --help                Show this help message and exit

Environment Variables:
  AWS_REGION_A              Default for --region-a
  AWS_REGION_B              Default for --region-b
  AWS_INSTANCE_TYPE         Default for --instance-type
  SSH_USER                  Default for --ssh-user
  AWS_AMI_A, AWS_AMI_B      Default AMI overrides
EOF
}

# ── argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --region-a)
            [[ -n "${2:-}" ]] || die "--region-a requires an argument"
            REGION_A="$2"
            shift 2
            ;;
        --region-b)
            [[ -n "${2:-}" ]] || die "--region-b requires an argument"
            REGION_B="$2"
            shift 2
            ;;
        --instance-type)
            [[ -n "${2:-}" ]] || die "--instance-type requires an argument"
            INSTANCE_TYPE="$2"
            shift 2
            ;;
        --ssh-user)
            [[ -n "${2:-}" ]] || die "--ssh-user requires an argument"
            SSH_USER="$2"
            shift 2
            ;;
        --ami-a)
            [[ -n "${2:-}" ]] || die "--ami-a requires an argument"
            AMI_A="$2"
            shift 2
            ;;
        --ami-b)
            [[ -n "${2:-}" ]] || die "--ami-b requires an argument"
            AMI_B="$2"
            shift 2
            ;;
        --key-file)
            [[ -n "${2:-}" ]] || die "--key-file requires an argument"
            KEY_FILE="$2"
            shift 2
            ;;
        --session-file)
            [[ -n "${2:-}" ]] || die "--session-file requires an argument"
            SESSION_FILE="$2"
            shift 2
            ;;
        --env-file)
            [[ -n "${2:-}" ]] || die "--env-file requires an argument"
            ENV_FILE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --skip-ssh-wait)
            SKIP_SSH_WAIT=1
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            die "unknown option: $1 (use --help for options)"
            ;;
    esac
done

# ── validation ──────────────────────────────────────────────────────────────
if [[ "$DRY_RUN" != "1" ]]; then
    command -v aws >/dev/null 2>&1 || die "AWS CLI (aws) is required but not installed in PATH."
fi
command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen is required but not installed in PATH."

RUN_ID="$(date +%s)"
TAG="yip-wan-bench-${RUN_ID}"
KEY_NAME="yip-wan-key-${RUN_ID}"
SG_NAME="yip-wan-sg-${RUN_ID}"

log "starting ephemeral WAN benchmark setup"
log "run ID:         $RUN_ID"
log "tag:            $TAG"
log "region A:       $REGION_A"
log "region B:       $REGION_B"
log "instance type:  $INSTANCE_TYPE"
log "ssh user:       $SSH_USER"
if [[ "$DRY_RUN" == "1" ]]; then
    log "mode:           DRY RUN"
fi

# ── public runner IP discovery ──────────────────────────────────────────────
get_runner_ip() {
    local ip=""
    for url in "https://checkip.amazonaws.com" "https://ifconfig.me" "https://api.ipify.org" "https://icanhazip.com"; do
        ip=$(curl -s --connect-timeout 4 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

RUNNER_IP=""
if [[ "$DRY_RUN" == "1" ]]; then
    RUNNER_IP="198.51.100.1"
    RUNNER_CIDR="$RUNNER_IP/32"
else
    RUNNER_IP="$(get_runner_ip || true)"
    if [[ -n "$RUNNER_IP" ]]; then
        RUNNER_CIDR="$RUNNER_IP/32"
        log "runner public IP detected: $RUNNER_IP"
    else
        warn "could not detect runner public IP, falling back to 0.0.0.0/0 for SSH ingress"
        RUNNER_IP="0.0.0.0"
        RUNNER_CIDR="0.0.0.0/0"
    fi
fi

# ── AMI resolution ──────────────────────────────────────────────────────────
resolve_ami() {
    local region="$1"
    local arch="x86_64"
    if [[ "$INSTANCE_TYPE" =~ ^(t4g|c7g|m7g|r7g|c6g|m6g|r6g) ]]; then
        arch="arm64"
    fi

    log "resolving Debian 12 AMI in $region ($arch)..."
    local ami
    # Try Debian 12 minimal first
    ami=$(aws ec2 describe-images \
        --region "$region" \
        --owners 136393095364 \
        --filters "Name=name,Values=debian-12-minimal-${arch}-*,debian-12-${arch}-*" "Name=state,Values=available" "Name=architecture,Values=${arch}" \
        --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
        --output text 2>/dev/null || true)
    if [[ -z "$ami" || "$ami" == "None" || "$ami" == "null" ]]; then
        ami=$(aws ec2 describe-images \
            --region "$region" \
            --owners 136393095364 \
            --filters "Name=name,Values=*debian-12*" "Name=state,Values=available" "Name=architecture,Values=${arch}" \
            --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
            --output text 2>/dev/null || true)
    fi
    [[ -n "$ami" && "$ami" != "None" && "$ami" != "null" ]] || die "could not resolve Debian 12 AMI in $region"
    echo "$ami"
}

if [[ "$DRY_RUN" == "1" ]]; then
    AMI_A="${AMI_A:-ami-dryrun00000000a}"
    AMI_B="${AMI_B:-ami-dryrun00000000b}"
else
    [[ -n "$AMI_A" ]] || AMI_A="$(resolve_ami "$REGION_A")"
    [[ -n "$AMI_B" ]] || AMI_B="$(resolve_ami "$REGION_B")"
fi
log "region A AMI:   $AMI_A"
log "region B AMI:   $AMI_B"

# ── keypair generation ──────────────────────────────────────────────────────
log "generating ephemeral ed25519 keypair at $KEY_FILE..."
mkdir -p "$(dirname "$KEY_FILE")"
rm -f "$KEY_FILE" "$KEY_FILE.pub"
ssh-keygen -t ed25519 -N "" -f "$KEY_FILE" -C "$TAG" >/dev/null 2>&1
chmod 600 "$KEY_FILE"
chmod 644 "$KEY_FILE.pub"

# ── AWS provisioning ────────────────────────────────────────────────────────
if [[ "$DRY_RUN" == "1" ]]; then
    SG_A="sg-dryrun00000000a"
    SG_B="sg-dryrun00000000b"
    INST_A="i-dryrun00000000a"
    INST_B="i-dryrun00000000b"
    IP_A="198.51.100.10"
    IP_B="203.0.113.20"
    log "dry-run: mock resources initialized"
else
    # Import keypair
    log "importing keypair $KEY_NAME to $REGION_A..."
    aws ec2 import-key-pair \
        --region "$REGION_A" \
        --key-name "$KEY_NAME" \
        --public-key-material "fileb://$KEY_FILE.pub" \
        --tag-specifications "ResourceType=key-pair,Tags=[{Key=Name,Value=$TAG},{Key=Project,Value=yip-wan-bench}]" >/dev/null

    log "importing keypair $KEY_NAME to $REGION_B..."
    aws ec2 import-key-pair \
        --region "$REGION_B" \
        --key-name "$KEY_NAME" \
        --public-key-material "fileb://$KEY_FILE.pub" \
        --tag-specifications "ResourceType=key-pair,Tags=[{Key=Name,Value=$TAG},{Key=Project,Value=yip-wan-bench}]" >/dev/null

    # Create security groups
    log "creating security group $SG_NAME in $REGION_A..."
    SG_A=$(aws ec2 create-security-group \
        --region "$REGION_A" \
        --group-name "$SG_NAME" \
        --description "Ephemeral security group for $TAG" \
        --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=$TAG},{Key=Project,Value=yip-wan-bench}]" \
        --query 'GroupId' --output text)

    log "authorizing SSH in $REGION_A from $RUNNER_CIDR..."
    aws ec2 authorize-security-group-ingress \
        --region "$REGION_A" \
        --group-id "$SG_A" \
        --protocol tcp \
        --port 22 \
        --cidr "$RUNNER_CIDR" >/dev/null

    log "creating security group $SG_NAME in $REGION_B..."
    SG_B=$(aws ec2 create-security-group \
        --region "$REGION_B" \
        --group-name "$SG_NAME" \
        --description "Ephemeral security group for $TAG" \
        --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=$TAG},{Key=Project,Value=yip-wan-bench}]" \
        --query 'GroupId' --output text)

    log "authorizing SSH in $REGION_B from $RUNNER_CIDR..."
    aws ec2 authorize-security-group-ingress \
        --region "$REGION_B" \
        --group-id "$SG_B" \
        --protocol tcp \
        --port 22 \
        --cidr "$RUNNER_CIDR" >/dev/null

    # Cloud-init user data ensuring root ssh key matches admin key if root access is invoked
    USER_DATA=$(cat <<'EOF'
#!/bin/bash
mkdir -p /root/.ssh
if [ -f /home/admin/.ssh/authorized_keys ]; then
  cp -f /home/admin/.ssh/authorized_keys /root/.ssh/authorized_keys
  chmod 700 /root/.ssh
  chmod 600 /root/.ssh/authorized_keys
fi
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null || true
systemctl reload ssh || systemctl restart ssh || service ssh restart || true
EOF
)
    USER_DATA_B64=$(echo "$USER_DATA" | base64 | tr -d '\n')

    # Launch instances
    log "launching instance in $REGION_A ($INSTANCE_TYPE, $AMI_A)..."
    INST_A=$(aws ec2 run-instances \
        --region "$REGION_A" \
        --image-id "$AMI_A" \
        --instance-type "$INSTANCE_TYPE" \
        --key-name "$KEY_NAME" \
        --security-group-ids "$SG_A" \
        --user-data "$USER_DATA_B64" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$TAG},{Key=Project,Value=yip-wan-bench},{Key=Role,Value=host-a}]" \
        --query 'Instances[0].InstanceId' --output text)

    log "launching instance in $REGION_B ($INSTANCE_TYPE, $AMI_B)..."
    INST_B=$(aws ec2 run-instances \
        --region "$REGION_B" \
        --image-id "$AMI_B" \
        --instance-type "$INSTANCE_TYPE" \
        --key-name "$KEY_NAME" \
        --security-group-ids "$SG_B" \
        --user-data "$USER_DATA_B64" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$TAG},{Key=Project,Value=yip-wan-bench},{Key=Role,Value=host-b}]" \
        --query 'Instances[0].InstanceId' --output text)

    # Wait for running
    log "waiting for instance $INST_A in $REGION_A to reach running state..."
    aws ec2 wait instance-running --region "$REGION_A" --instance-ids "$INST_A"
    log "waiting for instance $INST_B in $REGION_B to reach running state..."
    aws ec2 wait instance-running --region "$REGION_B" --instance-ids "$INST_B"

    # Fetch public IPs
    IP_A=$(aws ec2 describe-instances --region "$REGION_A" --instance-ids "$INST_A" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
    IP_B=$(aws ec2 describe-instances --region "$REGION_B" --instance-ids "$INST_B" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

    [[ -n "$IP_A" && "$IP_A" != "None" ]] || die "failed to obtain public IP for instance $INST_A"
    [[ -n "$IP_B" && "$IP_B" != "None" ]] || die "failed to obtain public IP for instance $INST_B"

    # Authorize cross-region peering ports between instances
    log "authorizing cross-region peering ingress (UDP 51833..51835, TCP/UDP 5201)..."
    for port in 51833 51834 51835 5201; do
        aws ec2 authorize-security-group-ingress --region "$REGION_A" --group-id "$SG_A" --protocol udp --port "$port" --cidr "$IP_B/32" >/dev/null
        aws ec2 authorize-security-group-ingress --region "$REGION_B" --group-id "$SG_B" --protocol udp --port "$port" --cidr "$IP_A/32" >/dev/null
    done
    aws ec2 authorize-security-group-ingress --region "$REGION_A" --group-id "$SG_A" --protocol tcp --port 5201 --cidr "$IP_B/32" >/dev/null
    aws ec2 authorize-security-group-ingress --region "$REGION_B" --group-id "$SG_B" --protocol tcp --port 5201 --cidr "$IP_A/32" >/dev/null
    aws ec2 authorize-security-group-ingress --region "$REGION_A" --group-id "$SG_A" --protocol icmp --port -1 --cidr "$IP_B/32" >/dev/null 2>&1 || true
    aws ec2 authorize-security-group-ingress --region "$REGION_B" --group-id "$SG_B" --protocol icmp --port -1 --cidr "$IP_A/32" >/dev/null 2>&1 || true
fi

# ── session metadata emission ───────────────────────────────────────────────
mkdir -p "$(dirname "$SESSION_FILE")"
cat <<EOF > "$SESSION_FILE.tmp"
{
  "run_id": "$RUN_ID",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tag": "$TAG",
  "key_name": "$KEY_NAME",
  "key_file": "$KEY_FILE",
  "ssh_user": "$SSH_USER",
  "instance_type": "$INSTANCE_TYPE",
  "region_a": {
    "region": "$REGION_A",
    "instance_id": "$INST_A",
    "security_group_id": "$SG_A",
    "public_ip": "$IP_A"
  },
  "region_b": {
    "region": "$REGION_B",
    "instance_id": "$INST_B",
    "security_group_id": "$SG_B",
    "public_ip": "$IP_B"
  }
}
EOF
mv -f "$SESSION_FILE.tmp" "$SESSION_FILE"
log "emitted session metadata -> $SESSION_FILE"

HOST_A="$IP_A"
HOST_B="$IP_B"

# ── wan.env emission ────────────────────────────────────────────────────────
mkdir -p "$(dirname "$ENV_FILE")"
cat <<EOF > "$ENV_FILE.tmp"
# Auto-generated by aws-up.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
HOST_A=$HOST_A
HOST_B=$HOST_B
HOST_A_LABEL="EC2 $REGION_A ($INSTANCE_TYPE)"
HOST_B_LABEL="EC2 $REGION_B ($INSTANCE_TYPE)"
SSH_USER=$SSH_USER
SSH_KEY=$KEY_FILE
YIP_PORT=51833
WG_PORT=51834
OVPN_PORT=51835
OVERLAY_MTU=1380
EOF
mv -f "$ENV_FILE.tmp" "$ENV_FILE"
log "emitted benchmark environment -> $ENV_FILE"

# ── SSH availability check ──────────────────────────────────────────────────
if [[ "$SKIP_SSH_WAIT" != "1" && "$DRY_RUN" != "1" ]]; then
    log "waiting for SSH accessibility on $HOST_A ($IP_A) and $HOST_B ($IP_B)..."
    wait_for_ssh() {
        local host="$1"
        local deadline=$((SECONDS + 120))
        while (( SECONDS < deadline )); do
            if ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -i "$KEY_FILE" "$SSH_USER@$host" "true" >/dev/null 2>&1; then
                return 0
            fi
            sleep 3
        done
        return 1
    }

    wait_for_ssh "$IP_A" || die "timed out waiting for SSH on Host A ($IP_A)"
    wait_for_ssh "$IP_B" || die "timed out waiting for SSH on Host B ($IP_B)"
    log "SSH is ready on both hosts!"
fi

log "ephemeral AWS environment is UP and ready."
log "  Host A: $IP_A ($REGION_A)"
log "  Host B: $IP_B ($REGION_B)"
log "To tear down when finished, run: $(dirname "$0")/aws-down.sh"
