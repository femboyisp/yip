#!/usr/bin/env bash
# Standalone test script for Multi-Engine DPI Oracle Parsers & Evaluator Gating (#70).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORACLE_SCRIPT="$SCRIPT_DIR/run-multi-dpi-oracle.sh"

echo "=== Testing Multi-Engine DPI Oracle Parsers ==="
TMP_TEST_DIR="$(mktemp -d /tmp/yipd-multi-dpi-unit-test.XXXXXX)"

cleanup() {
    rm -rf "$TMP_TEST_DIR"
}
trap cleanup EXIT

# Source oracle logic without triggering main
# shellcheck source=bin/yipd/tests/run-multi-dpi-oracle.sh
source "$ORACLE_SCRIPT"

TOTAL_TESTS=0
PASSED_TESTS=0

assert_eq() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [ "$expected" = "$actual" ]; then
        echo "  [OK] $test_name -> $actual"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "  [FAIL] $test_name"
        echo "    Expected: '$expected'"
        echo "    Actual:   '$actual'"
        exit 1
    fi
}

assert_match() {
    local test_name="$1"
    local pattern="$2"
    local actual="$3"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [[ "$actual" =~ $pattern ]]; then
        echo "  [OK] $test_name -> $actual"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "  [FAIL] $test_name"
        echo "    Pattern:  '$pattern'"
        echo "    Actual:   '$actual'"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# 1. Tool Checking Tests
# -----------------------------------------------------------------------------
echo "[Test Suite 1] Tool Detection"
if check_tool "bash"; then
    assert_eq "check_tool finds bash" "0" "0"
else
    assert_eq "check_tool finds bash" "0" "1"
fi

if check_tool "non_existent_tool_binary_xyz_123"; then
    assert_eq "check_tool fails for non_existent_tool" "1" "0"
else
    assert_eq "check_tool fails for non_existent_tool" "1" "1"
fi

# -----------------------------------------------------------------------------
# 2. nDPI Evaluator Parser Tests
# -----------------------------------------------------------------------------
echo "[Test Suite 2] nDPI Evaluator Parser"

# 2.1 raw-obf
mkdir -p "$TMP_TEST_DIR/ndpi_obf_pass"
cat > "$TMP_TEST_DIR/ndpi_obf_pass/ndpi-raw-obf.log" <<'EOF'
[proto: 0/Unknown][Stack: Unknown][IP: 10.0.9.1:34567 <-> 10.0.9.2:34567]
[risk: Susp Entropy]
Packets: 24, Bytes: 3200
EOF
res="$(eval_ndpi "raw-obf" "dummy.pcap" "$TMP_TEST_DIR/ndpi_obf_pass")"
assert_eq "eval_ndpi raw-obf PASS (Unknown with Susp Entropy ignored)" "PASS (Unknown)" "$res"

mkdir -p "$TMP_TEST_DIR/ndpi_obf_fail_wg"
cat > "$TMP_TEST_DIR/ndpi_obf_fail_wg/ndpi-raw-obf.log" <<'EOF'
[proto: 155/WireGuard][Stack: WireGuard][cat: VPN]
Packets: 24, Bytes: 3200
EOF
res="$(eval_ndpi "raw-obf" "dummy.pcap" "$TMP_TEST_DIR/ndpi_obf_fail_wg")"
assert_match "eval_ndpi raw-obf FAIL on WireGuard" "^FAIL" "$res"

mkdir -p "$TMP_TEST_DIR/ndpi_obf_fail_risk"
cat > "$TMP_TEST_DIR/ndpi_obf_fail_risk/ndpi-raw-obf.log" <<'EOF'
[proto: 0/Unknown]
** Obfuscated Traffic **
EOF
res="$(eval_ndpi "raw-obf" "dummy.pcap" "$TMP_TEST_DIR/ndpi_obf_fail_risk")"
assert_eq "eval_ndpi raw-obf FAIL on Obfuscated Traffic risk" "FAIL (Obfuscated Traffic risk)" "$res"

# 2.2 quic
mkdir -p "$TMP_TEST_DIR/ndpi_quic_pass"
cat > "$TMP_TEST_DIR/ndpi_quic_pass/ndpi-quic.log" <<'EOF'
[proto: 188.220/QUIC.Cloudflare][Stack: QUIC.Cloudflare]
Packets: 40, Bytes: 5200
EOF
res="$(eval_ndpi "quic" "dummy.pcap" "$TMP_TEST_DIR/ndpi_quic_pass")"
assert_eq "eval_ndpi quic PASS" "PASS (QUIC)" "$res"

mkdir -p "$TMP_TEST_DIR/ndpi_quic_fail_entropy"
cat > "$TMP_TEST_DIR/ndpi_quic_fail_entropy/ndpi-quic.log" <<'EOF'
[proto: 188.220/QUIC.Cloudflare]
** Susp Entropy **
EOF
res="$(eval_ndpi "quic" "dummy.pcap" "$TMP_TEST_DIR/ndpi_quic_fail_entropy")"
assert_eq "eval_ndpi quic FAIL on Susp Entropy" "FAIL (Susp Entropy risk)" "$res"

mkdir -p "$TMP_TEST_DIR/ndpi_quic_fail_unknown"
cat > "$TMP_TEST_DIR/ndpi_quic_fail_unknown/ndpi-quic.log" <<'EOF'
[proto: 0/Unknown]
EOF
res="$(eval_ndpi "quic" "dummy.pcap" "$TMP_TEST_DIR/ndpi_quic_fail_unknown")"
assert_eq "eval_ndpi quic FAIL on Unknown flow" "FAIL (flow not QUIC)" "$res"

# 2.3 tls
mkdir -p "$TMP_TEST_DIR/ndpi_tls_pass"
cat > "$TMP_TEST_DIR/ndpi_tls_pass/ndpi-tls.log" <<'EOF'
[proto: 91/TLS][Stack: TLS][Hostname: gateway.icloud.com]
Packets: 32, Bytes: 4800
EOF
res="$(eval_ndpi "tls" "dummy.pcap" "$TMP_TEST_DIR/ndpi_tls_pass")"
assert_eq "eval_ndpi tls PASS" "PASS (TLS+SNI)" "$res"

mkdir -p "$TMP_TEST_DIR/ndpi_tls_fail_sni"
cat > "$TMP_TEST_DIR/ndpi_tls_fail_sni/ndpi-tls.log" <<'EOF'
[proto: 91/TLS][Stack: TLS][Hostname: other.domain.com]
EOF
res="$(eval_ndpi "tls" "dummy.pcap" "$TMP_TEST_DIR/ndpi_tls_fail_sni")"
assert_match "eval_ndpi tls FAIL on SNI mismatch" "^FAIL.*SNI.*not detected" "$res"

# 2.4 relay
mkdir -p "$TMP_TEST_DIR/ndpi_relay_pass"
cat > "$TMP_TEST_DIR/ndpi_relay_pass/ndpi-relay.log" <<'EOF'
[proto: 91/TLS][Stack: TLS]
Packets: 18, Bytes: 2400
EOF
res="$(eval_ndpi "relay" "dummy.pcap" "$TMP_TEST_DIR/ndpi_relay_pass")"
assert_eq "eval_ndpi relay PASS" "PASS (TLS Front)" "$res"

mkdir -p "$TMP_TEST_DIR/ndpi_relay_fail_ovpn"
cat > "$TMP_TEST_DIR/ndpi_relay_fail_ovpn/ndpi-relay.log" <<'EOF'
[proto: 5/OpenVPN][Stack: OpenVPN]
EOF
res="$(eval_ndpi "relay" "dummy.pcap" "$TMP_TEST_DIR/ndpi_relay_fail_ovpn")"
assert_match "eval_ndpi relay FAIL on OpenVPN" "^FAIL" "$res"

# -----------------------------------------------------------------------------
# 3. tshark Evaluator Parser Tests
# -----------------------------------------------------------------------------
echo "[Test Suite 3] tshark Evaluator Parser"

# 3.1 raw-obf
mkdir -p "$TMP_TEST_DIR/tshark_obf_pass"
echo "eth:ethertype:ip:udp:data" > "$TMP_TEST_DIR/tshark_obf_pass/tshark-raw-obf-fields.txt"
echo "Frames: 20, Protocol: data" > "$TMP_TEST_DIR/tshark_obf_pass/tshark-raw-obf-phs.txt"
res="$(eval_tshark "raw-obf" "dummy.pcap" "$TMP_TEST_DIR/tshark_obf_pass")"
assert_eq "eval_tshark raw-obf PASS" "PASS (Data/UDP)" "$res"

mkdir -p "$TMP_TEST_DIR/tshark_obf_fail_wg"
echo "eth:ethertype:ip:udp:wireguard" > "$TMP_TEST_DIR/tshark_obf_fail_wg/tshark-raw-obf-fields.txt"
echo "Protocol: wireguard" > "$TMP_TEST_DIR/tshark_obf_fail_wg/tshark-raw-obf-phs.txt"
res="$(eval_tshark "raw-obf" "dummy.pcap" "$TMP_TEST_DIR/tshark_obf_fail_wg")"
assert_eq "eval_tshark raw-obf FAIL on wireguard" "FAIL (VPN dissector detected)" "$res"

# 3.2 quic
mkdir -p "$TMP_TEST_DIR/tshark_quic_pass"
echo "eth:ethertype:ip:udp:quic" > "$TMP_TEST_DIR/tshark_quic_pass/tshark-quic-fields.txt"
echo "Protocol: quic" > "$TMP_TEST_DIR/tshark_quic_pass/tshark-quic-phs.txt"
res="$(eval_tshark "quic" "dummy.pcap" "$TMP_TEST_DIR/tshark_quic_pass")"
assert_eq "eval_tshark quic PASS" "PASS (quic)" "$res"

mkdir -p "$TMP_TEST_DIR/tshark_quic_fail"
echo "eth:ethertype:ip:udp:data" > "$TMP_TEST_DIR/tshark_quic_fail/tshark-quic-fields.txt"
echo "Protocol: data" > "$TMP_TEST_DIR/tshark_quic_fail/tshark-quic-phs.txt"
res="$(eval_tshark "quic" "dummy.pcap" "$TMP_TEST_DIR/tshark_quic_fail")"
assert_eq "eval_tshark quic FAIL on missing quic" "FAIL (quic not detected in protocols)" "$res"

# 3.3 tls
mkdir -p "$TMP_TEST_DIR/tshark_tls_pass"
echo "eth:ethertype:ip:tcp:tls	gateway.icloud.com" > "$TMP_TEST_DIR/tshark_tls_pass/tshark-tls-fields.txt"
echo "Protocol: tls" > "$TMP_TEST_DIR/tshark_tls_pass/tshark-tls-phs.txt"
res="$(eval_tshark "tls" "dummy.pcap" "$TMP_TEST_DIR/tshark_tls_pass")"
assert_eq "eval_tshark tls PASS" "PASS (tls+SNI)" "$res"

mkdir -p "$TMP_TEST_DIR/tshark_tls_fail_sni"
echo "eth:ethertype:ip:tcp:tls	other.server.com" > "$TMP_TEST_DIR/tshark_tls_fail_sni/tshark-tls-fields.txt"
echo "Protocol: tls" > "$TMP_TEST_DIR/tshark_tls_fail_sni/tshark-tls-phs.txt"
res="$(eval_tshark "tls" "dummy.pcap" "$TMP_TEST_DIR/tshark_tls_fail_sni")"
assert_match "eval_tshark tls FAIL on SNI mismatch" "^FAIL.*SNI" "$res"

# 3.4 relay
mkdir -p "$TMP_TEST_DIR/tshark_relay_pass"
echo "eth:ethertype:ip:tcp:tls	gateway.icloud.com" > "$TMP_TEST_DIR/tshark_relay_pass/tshark-relay-fields.txt"
echo "Protocol: tls" > "$TMP_TEST_DIR/tshark_relay_pass/tshark-relay-phs.txt"
res="$(eval_tshark "relay" "dummy.pcap" "$TMP_TEST_DIR/tshark_relay_pass")"
assert_eq "eval_tshark relay PASS" "PASS (tls+SNI)" "$res"

# -----------------------------------------------------------------------------
# 4. Suricata Evaluator Parser Tests
# -----------------------------------------------------------------------------
echo "[Test Suite 4] Suricata Evaluator Parser"

# 4.1 raw-obf
mkdir -p "$TMP_TEST_DIR/suricata_obf_pass"
cat > "$TMP_TEST_DIR/suricata_obf_pass/eve.json" <<'EOF'
{"timestamp":"2026-10-15T22:00:00.000000","event_type":"flow","app_proto":"failed"}
EOF
res="$(eval_suricata "raw-obf" "dummy.pcap" "$TMP_TEST_DIR/suricata_obf_pass")"
assert_eq "eval_suricata raw-obf PASS (0 alerts, failed app_proto)" "PASS (0 alerts)" "$res"

mkdir -p "$TMP_TEST_DIR/suricata_obf_fail_alert"
cat > "$TMP_TEST_DIR/suricata_obf_fail_alert/eve.json" <<'EOF'
{"timestamp":"2026-10-15T22:00:00.000000","event_type":"alert","alert":{"signature":"ET TROJAN WireGuard VPN Handshake","category":"Tunneling"}}
EOF
res="$(eval_suricata "raw-obf" "dummy.pcap" "$TMP_TEST_DIR/suricata_obf_fail_alert")"
assert_match "eval_suricata raw-obf FAIL on alert" "^FAIL.*alert" "$res"

# 4.2 quic
mkdir -p "$TMP_TEST_DIR/suricata_quic_pass"
cat > "$TMP_TEST_DIR/suricata_quic_pass/eve.json" <<'EOF'
{"timestamp":"2026-10-15T22:00:00.000000","event_type":"flow","app_proto":"quic"}
EOF
res="$(eval_suricata "quic" "dummy.pcap" "$TMP_TEST_DIR/suricata_quic_pass")"
assert_eq "eval_suricata quic PASS" "PASS (0 alerts, quic)" "$res"

# 4.3 tls
mkdir -p "$TMP_TEST_DIR/suricata_tls_pass"
cat > "$TMP_TEST_DIR/suricata_tls_pass/eve.json" <<'EOF'
{"timestamp":"2026-10-15T22:00:00.000000","event_type":"tls","app_proto":"tls","tls":{"sni":"gateway.icloud.com"}}
EOF
res="$(eval_suricata "tls" "dummy.pcap" "$TMP_TEST_DIR/suricata_tls_pass")"
assert_eq "eval_suricata tls PASS" "PASS (0 alerts, tls)" "$res"

mkdir -p "$TMP_TEST_DIR/suricata_tls_fail_sni"
cat > "$TMP_TEST_DIR/suricata_tls_fail_sni/eve.json" <<'EOF'
{"timestamp":"2026-10-15T22:00:00.000000","event_type":"tls","app_proto":"tls","tls":{"sni":"wrong.server.com"}}
EOF
res="$(eval_suricata "tls" "dummy.pcap" "$TMP_TEST_DIR/suricata_tls_fail_sni")"
assert_match "eval_suricata tls FAIL on SNI mismatch" "^FAIL.*SNI" "$res"

# 4.4 relay
mkdir -p "$TMP_TEST_DIR/suricata_relay_pass"
cat > "$TMP_TEST_DIR/suricata_relay_pass/eve.json" <<'EOF'
{"timestamp":"2026-10-15T22:00:00.000000","event_type":"flow","app_proto":"tls"}
EOF
res="$(eval_suricata "relay" "dummy.pcap" "$TMP_TEST_DIR/suricata_relay_pass")"
assert_eq "eval_suricata relay PASS" "PASS (0 alerts)" "$res"

# -----------------------------------------------------------------------------
# 5. Zeek Evaluator Parser Tests
# -----------------------------------------------------------------------------
echo "[Test Suite 5] Zeek Evaluator Parser"

# 5.1 raw-obf
mkdir -p "$TMP_TEST_DIR/zeek_obf_pass"
cat > "$TMP_TEST_DIR/zeek_obf_pass/conn.log" <<'EOF'
#separator \x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state
1700000000.0	CH123	10.0.9.1	34567	10.0.9.2	34567	udp	-	0.5	100	100	SF
EOF
res="$(eval_zeek "raw-obf" "dummy.pcap" "$TMP_TEST_DIR/zeek_obf_pass")"
assert_eq "eval_zeek raw-obf PASS" "PASS (0 notices)" "$res"

mkdir -p "$TMP_TEST_DIR/zeek_obf_fail_notice"
cat > "$TMP_TEST_DIR/zeek_obf_fail_notice/conn.log" <<'EOF'
#separator \x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service
1700000000.0	CH123	10.0.9.1	34567	10.0.9.2	34567	udp	-
EOF
cat > "$TMP_TEST_DIR/zeek_obf_fail_notice/notice.log" <<'EOF'
#separator \x09
#fields	ts	note	msg
1700000000.0	Tunnel::Discovered	WireGuard proxy detected
EOF
res="$(eval_zeek "raw-obf" "dummy.pcap" "$TMP_TEST_DIR/zeek_obf_fail_notice")"
assert_match "eval_zeek raw-obf FAIL on notice" "^FAIL.*notice" "$res"

# 5.2 quic
mkdir -p "$TMP_TEST_DIR/zeek_quic_pass"
cat > "$TMP_TEST_DIR/zeek_quic_pass/conn.log" <<'EOF'
#separator \x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service
1700000000.0	CH124	10.0.10.1	34567	10.0.10.2	34567	udp	quic
EOF
res="$(eval_zeek "quic" "dummy.pcap" "$TMP_TEST_DIR/zeek_quic_pass")"
assert_eq "eval_zeek quic PASS" "PASS (0 notices, quic)" "$res"

# 5.3 tls
mkdir -p "$TMP_TEST_DIR/zeek_tls_pass"
cat > "$TMP_TEST_DIR/zeek_tls_pass/conn.log" <<'EOF'
#separator \x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service
1700000000.0	CH125	10.0.11.1	34567	10.0.11.2	34567	tcp	ssl
EOF
cat > "$TMP_TEST_DIR/zeek_tls_pass/ssl.log" <<'EOF'
#separator \x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	server_name
1700000000.0	CH125	10.0.11.1	34567	10.0.11.2	34567	gateway.icloud.com
EOF
res="$(eval_zeek "tls" "dummy.pcap" "$TMP_TEST_DIR/zeek_tls_pass")"
assert_eq "eval_zeek tls PASS" "PASS (0 notices, ssl)" "$res"

mkdir -p "$TMP_TEST_DIR/zeek_tls_fail_sni"
cat > "$TMP_TEST_DIR/zeek_tls_fail_sni/conn.log" <<'EOF'
#separator \x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service
1700000000.0	CH125	10.0.11.1	34567	10.0.11.2	34567	tcp	ssl
EOF
cat > "$TMP_TEST_DIR/zeek_tls_fail_sni/ssl.log" <<'EOF'
#separator \x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	server_name
1700000000.0	CH125	10.0.11.1	34567	10.0.11.2	34567	wrong.target.com
EOF
res="$(eval_zeek "tls" "dummy.pcap" "$TMP_TEST_DIR/zeek_tls_fail_sni")"
assert_match "eval_zeek tls FAIL on SNI mismatch" "^FAIL.*server_name" "$res"

# 5.4 relay
mkdir -p "$TMP_TEST_DIR/zeek_relay_pass"
cat > "$TMP_TEST_DIR/zeek_relay_pass/conn.log" <<'EOF'
#separator \x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service
1700000000.0	CH126	10.0.12.1	443	10.0.12.2	54321	tcp	ssl
EOF
res="$(eval_zeek "relay" "dummy.pcap" "$TMP_TEST_DIR/zeek_relay_pass")"
assert_eq "eval_zeek relay PASS" "PASS (0 notices, ssl)" "$res"

# -----------------------------------------------------------------------------
# 6. Verdict Table & Exit Code Tests
# -----------------------------------------------------------------------------
echo "[Test Suite 6] Verdict Table Formatting & Exit Code"

TABLE_DIR="$TMP_TEST_DIR/table_test"
mkdir -p "$TABLE_DIR"

# 6.1 All PASS
all_pass_args=(
    "raw_obf_ndpi=PASS (Unknown)"
    "raw_obf_tshark=PASS (Data/UDP)"
    "raw_obf_suricata=PASS (0 alerts)"
    "raw_obf_zeek=PASS (0 notices)"
    "quic_ndpi=PASS (QUIC)"
    "quic_tshark=PASS (quic)"
    "quic_suricata=PASS (0 alerts, quic)"
    "quic_zeek=PASS (0 notices, quic)"
    "tls_ndpi=PASS (TLS+SNI)"
    "tls_tshark=PASS (tls+SNI)"
    "tls_suricata=PASS (0 alerts, tls)"
    "tls_zeek=PASS (0 notices, ssl)"
    "relay_ndpi=PASS (TLS Front)"
    "relay_tshark=PASS (tls+SNI)"
    "relay_suricata=PASS (0 alerts)"
    "relay_zeek=PASS (0 notices, ssl)"
)

IS_CI="false"
format_verdict_table "$TABLE_DIR" "${all_pass_args[@]}" >/dev/null
rc=$?
assert_eq "format_verdict_table returns 0 on all PASS" "0" "$rc"
grep -q "\`raw/obf\` | PASS (Unknown) | PASS (Data/UDP) | PASS (0 alerts) | PASS (0 notices) | \*\*PASS\*\*" "$TABLE_DIR/verdict-summary.md"
assert_eq "Markdown table contains valid raw/obf PASS row" "0" "$?"

# 6.2 One FAIL
one_fail_args=("${all_pass_args[@]}")
one_fail_args[0]="raw_obf_ndpi=FAIL (VPN detected)"
set +e
format_verdict_table "$TABLE_DIR" "${one_fail_args[@]}" >/dev/null
rc=$?
set -e
assert_eq "format_verdict_table returns 1 on cell FAIL" "1" "$rc"
grep -q "\`raw/obf\` | FAIL (VPN detected) | PASS (Data/UDP) | PASS (0 alerts) | PASS (0 notices) | \*\*FAIL\*\*" "$TABLE_DIR/verdict-summary.md"
assert_eq "Markdown table contains FAIL row" "0" "$?"

# 6.3 Missing tool / SKIP in CI mode
one_skip_args=("${all_pass_args[@]}")
one_skip_args[3]="raw_obf_zeek=SKIP (zeek missing)"

IS_CI="false"
format_verdict_table "$TABLE_DIR" "${one_skip_args[@]}" >/dev/null
rc=$?
assert_eq "format_verdict_table returns 0 on SKIP outside CI" "0" "$rc"

IS_CI="true"
set +e
format_verdict_table "$TABLE_DIR" "${one_skip_args[@]}" >/dev/null
rc=$?
set -e
assert_eq "format_verdict_table returns 1 on SKIP in CI (honesty guard)" "1" "$rc"

echo ""
echo "=== All $PASSED_TESTS/$TOTAL_TESTS Multi-Engine DPI Oracle parser unit tests passed! ==="
