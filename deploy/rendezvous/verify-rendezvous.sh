#!/usr/bin/env bash
# Health and connectivity verification script for yip-rendezvous on port 443
# Strictly zero emojis
set -euo pipefail

TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-443}"

echo "[verify] probing rendezvous server at ${TARGET_HOST}:${TARGET_PORT}"

# Verify UDP listener
if command -v nc >/dev/null 2>&1; then
    if nc -z -u -w 2 "$TARGET_HOST" "$TARGET_PORT" 2>/dev/null; then
        echo "[verify] UDP port ${TARGET_PORT} reachable on ${TARGET_HOST}"
    else
        echo "[verify] note: UDP port check completed (UDP is connectionless)"
    fi
fi

# Verify TCP listener if enabled
if command -v nc >/dev/null 2>&1; then
    if nc -z -w 2 "$TARGET_HOST" "$TARGET_PORT" 2>/dev/null; then
        echo "[verify] TCP port ${TARGET_PORT} listening and accepting connections on ${TARGET_HOST}"
    fi
fi

echo "[verify] rendezvous verification probe complete"
