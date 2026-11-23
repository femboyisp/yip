#!/usr/bin/env bash
# Health and connectivity verification script for yip-rendezvous on port 443
# Strictly zero emojis
set -euo pipefail

TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-443}"
FAILURES=0

echo "[verify] probing rendezvous server at ${TARGET_HOST}:${TARGET_PORT}"

# 1. Systemd service status check if local
if [ "$TARGET_HOST" = "127.0.0.1" ] || [ "$TARGET_HOST" = "localhost" ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        if systemctl is-active --quiet yip-rendezvous 2>/dev/null; then
            echo "[verify] systemd service yip-rendezvous is active and running"
        else
            echo "[verify] error: systemd service yip-rendezvous is NOT active" >&2
            FAILURES=$((FAILURES + 1))
        fi
    fi
fi

# 2. Verify UDP listener
UDP_OK=0
if command -v ss >/dev/null 2>&1 && ([ "$TARGET_HOST" = "127.0.0.1" ] || [ "$TARGET_HOST" = "localhost" ]); then
    if ss -uln | grep -q ":${TARGET_PORT} "; then
        echo "[verify] UDP socket bound and listening on port ${TARGET_PORT}"
        UDP_OK=1
    fi
fi

if [ "$UDP_OK" -eq 0 ] && command -v nc >/dev/null 2>&1; then
    if nc -z -u -w 2 "$TARGET_HOST" "$TARGET_PORT" 2>/dev/null; then
        echo "[verify] UDP port ${TARGET_PORT} reachable on ${TARGET_HOST}"
        UDP_OK=1
    fi
fi

if [ "$UDP_OK" -eq 0 ]; then
    echo "[verify] error: UDP port ${TARGET_PORT} could not be confirmed listening on ${TARGET_HOST}" >&2
    FAILURES=$((FAILURES + 1))
fi

if [ "$FAILURES" -gt 0 ]; then
    echo "[verify] rendezvous verification failed with ${FAILURES} errors" >&2
    exit 1
fi

echo "[verify] rendezvous verification probe complete (status: HEALTHY)"
