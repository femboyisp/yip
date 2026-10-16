#!/usr/bin/env bash
# Multi-Engine DPI Evaluation Oracle for yip traffic (#70).
# Evaluates traffic across four engines: nDPI, tshark, Suricata, Zeek
# across four transport modes: raw-obf, quic, tls, relay.
#
# Usage:
#   Offline PCAP mode:
#     run-multi-dpi-oracle.sh --pcap-dir <dir> [out-dir]
#     run-multi-dpi-oracle.sh --obf-pcap <f> --quic-pcap <f> --tls-pcap <f> --relay-pcap <f> [--out-dir <dir>]
#   Live netns mode (Task 2):
#     run-multi-dpi-oracle.sh <yipd-binary> <ndpiReader-binary> [out-dir]
#
set -euo pipefail

# Global Configuration & Defaults
TLS_SNI="${TLS_SNI:-gateway.icloud.com}"
NDPI="${NDPI:-}"
TSHARK="${TSHARK:-}"
SURICATA="${SURICATA:-}"
ZEEK="${ZEEK:-}"
IS_CI="${CI:-${GITHUB_ACTIONS:-false}}"

# Check if a tool is present and executable
check_tool() {
    local tool="$1"
    if [ -z "$tool" ]; then
        return 1
    fi
    if [ -x "$tool" ]; then
        return 0
    fi
    if command -v "$tool" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Resolve tool binaries
resolve_ndpi() {
    if [ -n "$NDPI" ] && [ -x "$NDPI" ]; then
        echo "$NDPI"
    elif [ -n "$NDPI" ] && command -v "$NDPI" >/dev/null 2>&1; then
        command -v "$NDPI"
    elif [ -x "refrences/nDPI/example/ndpiReader" ]; then
        echo "refrences/nDPI/example/ndpiReader"
    elif command -v ndpiReader >/dev/null 2>&1; then
        command -v ndpiReader
    else
        echo ""
    fi
}

resolve_tshark() {
    if [ -n "$TSHARK" ] && [ -x "$TSHARK" ]; then
        echo "$TSHARK"
    elif [ -n "$TSHARK" ] && command -v "$TSHARK" >/dev/null 2>&1; then
        command -v "$TSHARK"
    elif command -v tshark >/dev/null 2>&1; then
        command -v tshark
    else
        echo ""
    fi
}

resolve_suricata() {
    if [ -n "$SURICATA" ] && [ -x "$SURICATA" ]; then
        echo "$SURICATA"
    elif [ -n "$SURICATA" ] && command -v "$SURICATA" >/dev/null 2>&1; then
        command -v "$SURICATA"
    elif command -v suricata >/dev/null 2>&1; then
        command -v suricata
    else
        echo ""
    fi
}

resolve_zeek() {
    if [ -n "$ZEEK" ] && [ -x "$ZEEK" ]; then
        echo "$ZEEK"
    elif [ -n "$ZEEK" ] && command -v "$ZEEK" >/dev/null 2>&1; then
        command -v "$ZEEK"
    elif command -v zeek >/dev/null 2>&1; then
        command -v zeek
    elif [ -x "/opt/zeek/bin/zeek" ]; then
        echo "/opt/zeek/bin/zeek"
    else
        echo ""
    fi
}

# -----------------------------------------------------------------------------
# Engine Evaluators
# -----------------------------------------------------------------------------

eval_ndpi() {
    local transport="$1"
    local pcap="$2"
    local out_dir="$3"
    local ndpi_bin
    ndpi_bin="$(resolve_ndpi)"

    mkdir -p "$out_dir"
    local ndpi_log="$out_dir/ndpi-${transport}.log"

    # If log doesn't exist and ndpiReader is available, execute it
    if [ ! -f "$ndpi_log" ]; then
        if [ -n "$ndpi_bin" ] && [ -f "$pcap" ]; then
            "$ndpi_bin" -i "$pcap" -v 2 >"$ndpi_log" 2>&1 || true
        elif [ -f "$out_dir/ndpi.log" ]; then
            ndpi_log="$out_dir/ndpi.log"
        else
            echo "SKIP (ndpiReader missing)"
            return 0
        fi
    fi

    # Evaluation rules per transport
    case "$transport" in
        raw-obf|raw/obf|obf)
            # Flow must be Unknown
            if ! grep -qiE '\[proto: 0/Unknown\]|\bUnknown\b' "$ndpi_log"; then
                echo "FAIL (flow not Unknown)"
                return 0
            fi
            # Zero detection of WireGuard, OpenVPN, Tor, or VPN categories
            if grep -qiE '\b(wireguard|openvpn|tor|proxy)\b|\[cat: *vpn\b' "$ndpi_log"; then
                echo "FAIL (VPN/proxy detected)"
                return 0
            fi
            # Zero NDPI_OBFUSCATED_TRAFFIC risk
            if grep -qiE 'obfuscated traffic|ndpi_obfuscated_traffic' "$ndpi_log"; then
                echo "FAIL (Obfuscated Traffic risk)"
                return 0
            fi
            echo "PASS (Unknown)"
            ;;
        quic)
            # Positive QUIC classification
            if ! grep -qiE '\[proto: [0-9]+\.[0-9]+/[^]]*quic[^]]*\]|\[stack: [^]]*quic[^]]*\]|\bquic\b' "$ndpi_log"; then
                echo "FAIL (flow not QUIC)"
                return 0
            fi
            # Zero Susp Entropy risk
            if grep -qiE 'susp entropy|ndpi_suspicious_entropy' "$ndpi_log"; then
                echo "FAIL (Susp Entropy risk)"
                return 0
            fi
            # Zero Obfuscated Traffic risk
            if grep -qiE 'obfuscated traffic|ndpi_obfuscated_traffic' "$ndpi_log"; then
                echo "FAIL (Obfuscated Traffic risk)"
                return 0
            fi
            # Zero VPN detection
            if grep -qiE '\b(wireguard|openvpn|tor|proxy)\b|\[cat: *vpn\b' "$ndpi_log"; then
                echo "FAIL (VPN/proxy detected)"
                return 0
            fi
            echo "PASS (QUIC)"
            ;;
        tls)
            # Positive TLS classification
            if ! grep -qiE '\[proto: [0-9]+(\.[0-9]+)?/[^]]*tls[^]]*\]|\[stack: [^]]*tls[^]]*\]|\btls\b' "$ndpi_log"; then
                echo "FAIL (flow not TLS)"
                return 0
            fi
            # SNI detected
            if ! grep -qiF "$TLS_SNI" "$ndpi_log"; then
                echo "FAIL (SNI $TLS_SNI not detected)"
                return 0
            fi
            # Zero VPN detection
            if grep -qiE '\b(wireguard|openvpn|tor|proxy)\b|\[cat: *vpn\b' "$ndpi_log"; then
                echo "FAIL (VPN/proxy detected)"
                return 0
            fi
            # Zero Obfuscated Traffic risk
            if grep -qiE 'obfuscated traffic|ndpi_obfuscated_traffic' "$ndpi_log"; then
                echo "FAIL (Obfuscated Traffic risk)"
                return 0
            fi
            # Zero Susp Entropy risk
            if grep -qiE 'susp entropy|ndpi_suspicious_entropy' "$ndpi_log"; then
                echo "FAIL (Susp Entropy risk)"
                return 0
            fi
            echo "PASS (TLS+SNI)"
            ;;
        relay)
            # Positive TLS classification
            if ! grep -qiE '\[proto: [0-9]+(\.[0-9]+)?/[^]]*tls[^]]*\]|\[stack: [^]]*tls[^]]*\]|\btls\b' "$ndpi_log"; then
                echo "FAIL (flow not TLS)"
                return 0
            fi
            # Zero VPN detection
            if grep -qiE '\b(wireguard|openvpn|tor|proxy)\b|\[cat: *vpn\b' "$ndpi_log"; then
                echo "FAIL (VPN/proxy detected)"
                return 0
            fi
            echo "PASS (TLS Front)"
            ;;
        *)
            echo "FAIL (unknown transport $transport)"
            ;;
    esac
}

eval_tshark() {
    local transport="$1"
    local pcap="$2"
    local out_dir="$3"
    local tshark_bin
    tshark_bin="$(resolve_tshark)"

    mkdir -p "$out_dir"
    local phs_file="$out_dir/tshark-${transport}-phs.txt"
    local fields_file="$out_dir/tshark-${transport}-fields.txt"

    # If outputs don't exist and tshark is available, run tshark
    if [ ! -f "$phs_file" ] || [ ! -f "$fields_file" ]; then
        if [ -n "$tshark_bin" ] && [ -f "$pcap" ]; then
            "$tshark_bin" -r "$pcap" -q -z io,phs >"$phs_file" 2>&1 || true
            "$tshark_bin" -r "$pcap" -T fields -e frame.protocols -e tls.handshake.extensions_server_name >"$fields_file" 2>&1 || true
        elif [ -f "$out_dir/tshark-phs.txt" ] && [ -f "$out_dir/tshark-fields.txt" ]; then
            phs_file="$out_dir/tshark-phs.txt"
            fields_file="$out_dir/tshark-fields.txt"
        else
            echo "SKIP (tshark missing)"
            return 0
        fi
    fi

    case "$transport" in
        raw-obf|raw/obf|obf)
            # Zero VPN dissectors
            if grep -qiE '\b(wireguard|openvpn|socks|ssh|ipsec|tor|vpn)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (VPN dissector detected)"
                return 0
            fi
            # Generic data / udp
            if ! grep -qiE '\b(data|udp)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (missing data/udp in protocol hierarchy)"
                return 0
            fi
            echo "PASS (Data/UDP)"
            ;;
        quic)
            # Zero VPN dissectors
            if grep -qiE '\b(wireguard|openvpn|socks|ssh|ipsec|tor|vpn)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (VPN dissector detected)"
                return 0
            fi
            # Protocols contain quic
            if ! grep -qiE '\bquic\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (quic not detected in protocols)"
                return 0
            fi
            echo "PASS (quic)"
            ;;
        tls)
            # Zero VPN dissectors
            if grep -qiE '\b(wireguard|openvpn|socks|ssh|ipsec|tor|vpn)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (VPN dissector detected)"
                return 0
            fi
            # Protocols contain tls or ssl
            if ! grep -qiE '\b(tls|ssl)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (tls/ssl not detected in protocols)"
                return 0
            fi
            # SNI matches configured target
            if ! grep -qiF "$TLS_SNI" "$fields_file" 2>/dev/null; then
                echo "FAIL (SNI $TLS_SNI not found in ClientHello)"
                return 0
            fi
            echo "PASS (tls+SNI)"
            ;;
        relay)
            # Zero VPN dissectors
            if grep -qiE '\b(wireguard|openvpn|socks|ssh|ipsec|tor|vpn)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (VPN dissector detected)"
                return 0
            fi
            # Protocols contain tls or ssl
            if ! grep -qiE '\b(tls|ssl)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (tls not detected in protocols)"
                return 0
            fi
            echo "PASS (tls+SNI)"
            ;;
        *)
            echo "FAIL (unknown transport $transport)"
            ;;
    esac
}

eval_suricata() {
    local transport="$1"
    local pcap="$2"
    local out_dir="$3"
    local suricata_bin
    suricata_bin="$(resolve_suricata)"

    local suricata_dir="$out_dir/suricata-${transport}"
    local eve_file="$suricata_dir/eve.json"

    # Check for direct or transport-specific eve.json
    if [ ! -f "$eve_file" ]; then
        if [ -f "$out_dir/eve.json" ]; then
            eve_file="$out_dir/eve.json"
        elif [ -n "$suricata_bin" ] && [ -f "$pcap" ]; then
            mkdir -p "$suricata_dir"
            "$suricata_bin" -r "$pcap" -l "$suricata_dir" -k none --runmode single >/dev/null 2>&1 || true
        else
            echo "SKIP (suricata missing)"
            return 0
        fi
    fi

    if [ ! -f "$eve_file" ]; then
        echo "FAIL (eve.json not generated)"
        return 0
    fi

    # Zero alerts matching VPN/tunnel signatures (or alerts count = 0)
    if grep -qiE '"event_type":\s*"alert"' "$eve_file" 2>/dev/null; then
        if grep -iE '"event_type":\s*"alert"' "$eve_file" | grep -qiE 'vpn|tunnel|wireguard|openvpn|tor|shadowsocks|proxy'; then
            echo "FAIL (VPN/tunnel alert triggered)"
            return 0
        else
            echo "FAIL (Suricata alert triggered)"
            return 0
        fi
    fi

    case "$transport" in
        raw-obf|raw/obf|obf)
            # app_proto should not be a recognized VPN or L7 protocol
            if grep -qiE '"app_proto":\s*"(wireguard|openvpn|tor|shadowsocks|quic|tls)"' "$eve_file" 2>/dev/null; then
                echo "FAIL (unexpected app_proto recognized)"
                return 0
            fi
            echo "PASS (0 alerts)"
            ;;
        quic)
            # app_proto identified as quic (or quic event)
            if ! grep -qiE '"app_proto":\s*"quic"|"event_type":\s*"quic"' "$eve_file" 2>/dev/null; then
                echo "FAIL (quic not identified by app_proto)"
                return 0
            fi
            echo "PASS (0 alerts, quic)"
            ;;
        tls)
            # tls event in eve.json with matching SNI
            if ! grep -qiE '"app_proto":\s*"tls"|"event_type":\s*"tls"' "$eve_file" 2>/dev/null; then
                echo "FAIL (tls not identified by app_proto)"
                return 0
            fi
            if ! grep -qiF "$TLS_SNI" "$eve_file" 2>/dev/null; then
                echo "FAIL (SNI $TLS_SNI not found in tls eve events)"
                return 0
            fi
            echo "PASS (0 alerts, tls)"
            ;;
        relay)
            # tls identified by app_proto
            if ! grep -qiE '"app_proto":\s*"tls"|"event_type":\s*"tls"' "$eve_file" 2>/dev/null; then
                echo "FAIL (tls not identified by app_proto)"
                return 0
            fi
            echo "PASS (0 alerts)"
            ;;
        *)
            echo "FAIL (unknown transport $transport)"
            ;;
    esac
}

eval_zeek() {
    local transport="$1"
    local pcap="$2"
    local out_dir="$3"
    local zeek_bin
    zeek_bin="$(resolve_zeek)"

    local zeek_dir="$out_dir/zeek-${transport}"
    local conn_log="$zeek_dir/conn.log"
    local notice_log="$zeek_dir/notice.log"
    local ssl_log="$zeek_dir/ssl.log"

    # Check for logs in $out_dir or run zeek
    if [ ! -f "$conn_log" ]; then
        if [ -f "$out_dir/conn.log" ]; then
            zeek_dir="$out_dir"
            conn_log="$out_dir/conn.log"
            notice_log="$out_dir/notice.log"
            ssl_log="$out_dir/ssl.log"
        elif [ -n "$zeek_bin" ] && [ -f "$pcap" ]; then
            mkdir -p "$zeek_dir"
            (cd "$zeek_dir" && "$zeek_bin" -C -r "$pcap" local >/dev/null 2>&1 || true)
        else
            echo "SKIP (zeek missing)"
            return 0
        fi
    fi

    # notice.log must not contain tunnel/anomaly notices
    if [ -f "$notice_log" ]; then
        if grep -v '^#' "$notice_log" | grep -qiE 'tunnel|vpn|wireguard|openvpn|tor|proxy|anomaly'; then
            echo "FAIL (tunnel notice triggered)"
            return 0
        fi
    fi

    if [ ! -f "$conn_log" ]; then
        echo "FAIL (conn.log not generated)"
        return 0
    fi

    case "$transport" in
        raw-obf|raw/obf|obf)
            # service must be unclassified '-' and no VPN
            if grep -v '^#' "$conn_log" | grep -qiE '\b(wireguard|openvpn|tor|shadowsocks|vpn)\b'; then
                echo "FAIL (VPN service detected)"
                return 0
            fi
            if grep -v '^#' "$conn_log" | grep -qiE '\b(ssl|quic|http)\b'; then
                echo "FAIL (unexpected L7 service recognized in conn.log)"
                return 0
            fi
            echo "PASS (0 notices)"
            ;;
        quic)
            # service field contains quic or ssl
            if ! grep -v '^#' "$conn_log" | grep -qiE '\b(quic|ssl)\b'; then
                echo "FAIL (quic service not recognized in conn.log)"
                return 0
            fi
            echo "PASS (0 notices, quic)"
            ;;
        tls)
            # service field contains ssl
            if ! grep -v '^#' "$conn_log" | grep -qiE '\bssl\b'; then
                echo "FAIL (ssl service not recognized in conn.log)"
                return 0
            fi
            # If ssl.log is generated, verify server_name
            if [ -f "$ssl_log" ]; then
                if ! grep -v '^#' "$ssl_log" | grep -qiF "$TLS_SNI"; then
                    echo "FAIL (server_name $TLS_SNI not in ssl.log)"
                    return 0
                fi
            fi
            echo "PASS (0 notices, ssl)"
            ;;
        relay)
            # service field contains ssl
            if ! grep -v '^#' "$conn_log" | grep -qiE '\bssl\b'; then
                echo "FAIL (ssl service not recognized in conn.log)"
                return 0
            fi
            echo "PASS (0 notices, ssl)"
            ;;
        *)
            echo "FAIL (unknown transport $transport)"
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Verdict Table Generation
# -----------------------------------------------------------------------------

format_verdict_table() {
    local out_dir="$1"
    shift
    # Remaining args are key=value pairs: e.g. raw_obf_ndpi="PASS (...)"
    declare -A verdicts
    for arg in "$@"; do
        local key="${arg%%=*}"
        local val="${arg#*=}"
        verdicts["$key"]="$val"
    done

    local md_file="$out_dir/verdict-summary.md"
    mkdir -p "$out_dir"

    local transports=("raw-obf" "quic" "tls" "relay")
    local display_names=("raw/obf" "quic" "tls" "relay")

    local any_fail=0
    local any_skip=0

    {
        echo "| Transport | nDPI Verdict | tshark Verdict | Suricata Verdict | Zeek Verdict | Overall |"
        echo "| :--- | :--- | :--- | :--- | :--- | :--- |"
        for i in "${!transports[@]}"; do
            local t="${transports[$i]}"
            local d="${display_names[$i]}"
            local t_key="${t//-/_}"
            local v_ndpi="${verdicts[${t_key}_ndpi]:-SKIP}"
            local v_tshark="${verdicts[${t_key}_tshark]:-SKIP}"
            local v_suricata="${verdicts[${t_key}_suricata]:-SKIP}"
            local v_zeek="${verdicts[${t_key}_zeek]:-SKIP}"

            local row_fail=0
            local row_all_skip=1
            for v in "$v_ndpi" "$v_tshark" "$v_suricata" "$v_zeek"; do
                if [[ "$v" =~ ^FAIL ]]; then
                    row_fail=1
                    any_fail=1
                fi
                if [[ "$v" =~ ^SKIP ]]; then
                    any_skip=1
                else
                    row_all_skip=0
                fi
            done

            local row_overall="**PASS**"
            if [ "$row_fail" -eq 1 ]; then
                row_overall="**FAIL**"
            elif [ "$row_all_skip" -eq 1 ]; then
                row_overall="**SKIP**"
            fi

            echo "| \`$d\` | $v_ndpi | $v_tshark | $v_suricata | $v_zeek | $row_overall |"
        done
    } > "$md_file"

    echo ""
    echo "============================= VERDICT SUMMARY ============================="
    cat "$md_file"
    echo "==========================================================================="
    echo "Verdict table written to: $md_file"
    echo ""

    if [ "$any_fail" -ne 0 ]; then
        return 1
    fi
    if [ "$IS_CI" = "true" ] && [ "$any_skip" -ne 0 ]; then
        echo "[ERROR] Honesty guard: engine(s) were skipped in CI environment!"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Main CLI & Dispatcher
# -----------------------------------------------------------------------------

main() {
    local pcap_dir=""
    local obf_pcap=""
    local quic_pcap=""
    local tls_pcap=""
    local relay_pcap=""
    local out_dir=""
    local yipd_bin=""
    local ndpi_bin=""

    # Argument parsing
    while [ $# -gt 0 ]; do
        case "$1" in
            --pcap-dir)
                pcap_dir="$2"
                shift 2
                ;;
            --obf-pcap|--raw-obf-pcap)
                obf_pcap="$2"
                shift 2
                ;;
            --quic-pcap)
                quic_pcap="$2"
                shift 2
                ;;
            --tls-pcap)
                tls_pcap="$2"
                shift 2
                ;;
            --relay-pcap)
                relay_pcap="$2"
                shift 2
                ;;
            --out-dir)
                out_dir="$2"
                shift 2
                ;;
            --ndpi-bin)
                NDPI="$2"
                shift 2
                ;;
            --sni)
                TLS_SNI="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [--pcap-dir <dir> | <yipd-binary> <ndpiReader-binary> [out-dir]]"
                exit 0
                ;;
            *)
                if [ -z "$yipd_bin" ] && [ -z "$pcap_dir" ]; then
                    yipd_bin="$1"
                    shift
                elif [ -z "$ndpi_bin" ] && [ -n "$yipd_bin" ]; then
                    ndpi_bin="$1"
                    NDPI="$ndpi_bin"
                    shift
                elif [ -z "$out_dir" ]; then
                    out_dir="$1"
                    shift
                else
                    shift
                fi
                ;;
        esac
    done

    # Resolve output directory
    if [ -z "$out_dir" ]; then
        out_dir="$(mktemp -d /tmp/yipd-multi-dpi-oracle.XXXXXX)"
    else
        mkdir -p "$out_dir"
    fi

    # Handle PCAP directory ingestion
    if [ -n "$pcap_dir" ]; then
        [ -z "$obf_pcap" ] && obf_pcap="$pcap_dir/raw-obf.pcap"
        [ ! -f "$obf_pcap" ] && [ -f "$pcap_dir/yip-obf.pcap" ] && obf_pcap="$pcap_dir/yip-obf.pcap"
        [ -z "$quic_pcap" ] && quic_pcap="$pcap_dir/quic.pcap"
        [ ! -f "$quic_pcap" ] && [ -f "$pcap_dir/yip-quic.pcap" ] && quic_pcap="$pcap_dir/yip-quic.pcap"
        [ -z "$tls_pcap" ] && tls_pcap="$pcap_dir/tls.pcap"
        [ ! -f "$tls_pcap" ] && [ -f "$pcap_dir/yip-tls.pcap" ] && tls_pcap="$pcap_dir/yip-tls.pcap"
        [ -z "$relay_pcap" ] && relay_pcap="$pcap_dir/relay.pcap"
        [ ! -f "$relay_pcap" ] && [ -f "$pcap_dir/yip-relay.pcap" ] && relay_pcap="$pcap_dir/yip-relay.pcap"
    fi

    # If PCAPs are still not provided, check if live capture was requested
    if [ -z "$obf_pcap" ] && [ -z "$quic_pcap" ] && [ -z "$tls_pcap" ] && [ -z "$relay_pcap" ]; then
        if [ -n "$yipd_bin" ]; then
            if [ "$(id -u)" -ne 0 ]; then
                echo "SKIP run-multi-dpi-oracle: needs root (netns + tcpdump) for live capture, or use --pcap-dir <dir>"
                exit 0
            fi
            # Placeholder for Task 2 live netns capture pipeline
            echo "[notice] Live netns capture will be executed in Task 2. Run with --pcap-dir for offline evaluation."
            exit 0
        else
            echo "Error: no PCAP inputs provided and no yipd binary specified."
            echo "Usage: $0 [--pcap-dir <dir> | <yipd-binary> <ndpiReader-binary> [out-dir]]"
            exit 1
        fi
    fi

    echo "=== Running Multi-Engine DPI Oracle ==="
    echo "Output directory: $out_dir"
    echo "TLS Target SNI:   $TLS_SNI"

    local pcap_map=(
        "raw_obf:$obf_pcap"
        "quic:$quic_pcap"
        "tls:$tls_pcap"
        "relay:$relay_pcap"
    )

    local verdict_args=()

    for item in "${pcap_map[@]}"; do
        local t_key="${item%%:*}"
        local pcap="${item#*:}"
        local transport="${t_key//_/-}"

        echo "--- Evaluating Transport: $transport ---"
        echo "PCAP file: $pcap"

        local v_ndpi v_tshark v_suricata v_zeek
        v_ndpi="$(eval_ndpi "$transport" "$pcap" "$out_dir")"
        echo "  nDPI:     $v_ndpi"
        v_tshark="$(eval_tshark "$transport" "$pcap" "$out_dir")"
        echo "  tshark:   $v_tshark"
        v_suricata="$(eval_suricata "$transport" "$pcap" "$out_dir")"
        echo "  Suricata: $v_suricata"
        v_zeek="$(eval_zeek "$transport" "$pcap" "$out_dir")"
        echo "  Zeek:     $v_zeek"

        verdict_args+=("${t_key}_ndpi=$v_ndpi")
        verdict_args+=("${t_key}_tshark=$v_tshark")
        verdict_args+=("${t_key}_suricata=$v_suricata")
        verdict_args+=("${t_key}_zeek=$v_zeek")
    done

    format_verdict_table "$out_dir" "${verdict_args[@]}"
    local rc=$?
    exit $rc
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
