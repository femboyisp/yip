#!/usr/bin/env python3
"""
generate-architecture.py

Deterministic vector SVG system architecture diagram generator for yip.
Generates:
  assets/architecture.svg

Visualizes yip's dual-path pipeline:
  1. Top: Control Plane (#6366f1) - BLAKE2s, CA-Gated Mesh (yip-ca), NAT Hole-Punching & Relay (yip-rendezvous)
  2. Middle: Data Plane Pipeline (#06b6d4) - TUN/TAP (64KB GSO/GRO), SPSC Shards, ChaCha20-Poly1305, Systematic Cauchy RS-FEC (#f97316)
  3. Bottom Dual-Path:
     - Fast Path (#10b981): eBPF AF_XDP Zero-Copy (XSKMAP) + Vectorized epoll sendmmsg -> 40+ Gbps
     - Stealth / Anti-DPI Path (#e11d48 / #f97316): uTLS Chrome JA3/JA4 Parity + Xray-REALITY TLS 1.3/QUIC -> 4-Engine DPI Oracle

Standard library only. Strict determinism (fixed formatting, no timestamps).
"""

import argparse
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

FONT_SANS = "ui-sans-serif, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
FONT_MONO = "ui-monospace, SFMono-Regular, Menlo, monospace"

# Theme Palette (GitHub Dark Mode aligned)
COLOR_CANVAS_BG = "#0d1117"
COLOR_CANVAS_BORDER = "#30363d"
COLOR_CARD_BG = "#161b22"
COLOR_SUB_CARD_BG = "#0d1117"
COLOR_TEXT_WHITE = "#f0f6fc"
COLOR_TEXT_MUTED = "#8b949e"
COLOR_TEXT_DIM = "#6e7681"

# Domain Colors
COLOR_CONTROL = "#6366f1"       # Indigo
COLOR_CONTROL_LIGHT = "#818cf8"
COLOR_CONTROL_BG = "#1e1b4b"

COLOR_DATA = "#06b6d4"          # Cyan
COLOR_DATA_LIGHT = "#22d3ee"
COLOR_DATA_BG = "#083344"

COLOR_FEC = "#f97316"           # Fox Orange / Amber
COLOR_FEC_LIGHT = "#fb923c"
COLOR_FEC_BG = "#431407"

COLOR_FAST = "#10b981"          # Emerald Green
COLOR_FAST_LIGHT = "#34d399"
COLOR_FAST_BG = "#064e3b"

COLOR_STEALTH = "#e11d48"       # Rose Red
COLOR_STEALTH_LIGHT = "#fb7185"
COLOR_STEALTH_BG = "#4c0519"


def escape_xml(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def build_architecture_svg() -> str:
    w = 1040
    h = 736
    lines = []

    lines.append('<?xml version="1.0" encoding="UTF-8"?>')
    lines.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}">')

    # Definitions (Markers & Gradients)
    lines.append('  <defs>')
    # Arrow markers
    marker_colors = {
        "ctrl": COLOR_CONTROL,
        "data": COLOR_DATA,
        "fec": COLOR_FEC,
        "fast": COLOR_FAST,
        "stealth": COLOR_STEALTH,
        "dim": COLOR_TEXT_DIM,
    }
    for name, col in marker_colors.items():
        lines.append(f'    <marker id="arrow-{name}" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">')
        lines.append(f'      <path d="M0,0 L0,6 L6,3 z" fill="{col}" />')
        lines.append('    </marker>')

    # Subtle gradients
    lines.append('    <linearGradient id="grad-control-card" x1="0%" y1="0%" x2="0%" y2="100%">')
    lines.append('      <stop offset="0%" stop-color="#6366f1" stop-opacity="0.08" />')
    lines.append('      <stop offset="100%" stop-color="#161b22" stop-opacity="0.95" />')
    lines.append('    </linearGradient>')
    lines.append('    <linearGradient id="grad-data-card" x1="0%" y1="0%" x2="0%" y2="100%">')
    lines.append('      <stop offset="0%" stop-color="#06b6d4" stop-opacity="0.08" />')
    lines.append('      <stop offset="100%" stop-color="#161b22" stop-opacity="0.95" />')
    lines.append('    </linearGradient>')
    lines.append('    <linearGradient id="grad-fast-card" x1="0%" y1="0%" x2="0%" y2="100%">')
    lines.append('      <stop offset="0%" stop-color="#10b981" stop-opacity="0.08" />')
    lines.append('      <stop offset="100%" stop-color="#161b22" stop-opacity="0.95" />')
    lines.append('    </linearGradient>')
    lines.append('    <linearGradient id="grad-stealth-card" x1="0%" y1="0%" x2="0%" y2="100%">')
    lines.append('      <stop offset="0%" stop-color="#e11d48" stop-opacity="0.08" />')
    lines.append('      <stop offset="100%" stop-color="#161b22" stop-opacity="0.95" />')
    lines.append('    </linearGradient>')
    lines.append('    <linearGradient id="grad-fec-subcard" x1="0%" y1="0%" x2="0%" y2="100%">')
    lines.append('      <stop offset="0%" stop-color="#f97316" stop-opacity="0.12" />')
    lines.append('      <stop offset="100%" stop-color="#0d1117" stop-opacity="0.98" />')
    lines.append('    </linearGradient>')
    lines.append('  </defs>')

    # Background Canvas
    lines.append('  <!-- Canvas Background -->')
    lines.append(f'  <rect x="0.75" y="0.75" width="{w - 1.5:.2f}" height="{h - 1.5:.2f}" rx="12.00" fill="{COLOR_CANVAS_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.50" />')

    # =========================================================================
    # HEADER SECTION
    # =========================================================================
    lines.append('  <!-- Header -->')
    lines.append('  <g id="header">')
    # Engine Logo Badge (crisp vector fox icon + text)
    lines.append(f'    <rect x="24.00" y="20.00" width="76.00" height="24.00" rx="6.00" fill="{COLOR_FEC_BG}" stroke="{COLOR_FEC}" stroke-width="1.00" />')
    lines.append(f'    <polygon points="34.00,36.00 39.00,26.00 44.00,31.00 49.00,26.00 54.00,36.00 44.00,39.00" fill="{COLOR_FEC_LIGHT}" />')
    lines.append(f'    <text x="73.00" y="36.00" font-family="{FONT_MONO}" font-size="11" font-weight="700" fill="{COLOR_FEC_LIGHT}" text-anchor="middle">YIP</text>')

    # Title & Subtitle
    lines.append(f'    <text x="110.00" y="37.00" font-family="{FONT_SANS}" font-size="17" font-weight="700" fill="{COLOR_TEXT_WHITE}">DUAL-PATH SYSTEM ARCHITECTURE</text>')
    lines.append(f'    <text x="110.00" y="55.00" font-family="{FONT_SANS}" font-size="11.5" fill="{COLOR_TEXT_MUTED}">Zero-Lock Data Plane • eBPF AF_XDP 40 Gbps &amp; Anti-DPI Subsystems</text>')

    # Feature Badges on right
    badges = [
        ("40+ Gbps eBPF", COLOR_FAST_BG, COLOR_FAST_LIGHT, COLOR_FAST),
        ("GF(256) RS-FEC", COLOR_FEC_BG, COLOR_FEC_LIGHT, COLOR_FEC),
        ("t-of-n Threshold CA", COLOR_CONTROL_BG, COLOR_CONTROL_LIGHT, COLOR_CONTROL),
        ("ML-KEM-512 PQ", COLOR_CONTROL_BG, COLOR_CONTROL_LIGHT, COLOR_CONTROL),
    ]
    bx = w - 24
    for btext, bbg, bfg, bborder in reversed(badges):
        bw = len(btext) * 7.5 + 20
        bx -= bw
        lines.append(f'    <rect x="{bx:.2f}" y="{24.00:.2f}" width="{bw:.2f}" height="22.00" rx="11.00" fill="{bbg}" stroke="{bborder}" stroke-width="1.00" />')
        lines.append(f'    <text x="{bx + bw/2:.2f}" y="39.00" font-family="{FONT_MONO}" font-size="10" font-weight="600" fill="{bfg}" text-anchor="middle">{btext}</text>')
        bx -= 10
    lines.append('  </g>')

    # =========================================================================
    # SECTION 1: TOP CONTROL PLANE (#6366f1)
    # =========================================================================
    lines.append('  <!-- ========================================================= -->')
    lines.append('  <!-- SECTION 1: CONTROL PLANE                                 -->')
    lines.append('  <!-- ========================================================= -->')
    lines.append('  <g id="control-plane">')
    lines.append(f'    <rect x="24.00" y="74.00" width="992.00" height="120.00" rx="8.00" fill="url(#grad-control-card)" stroke="{COLOR_CONTROL}" stroke-width="1.20" stroke-opacity="0.70" />')

    # Section Header Pill with generous padding
    lines.append(f'    <rect x="36.00" y="84.00" width="124.00" height="18.00" rx="4.00" fill="{COLOR_CONTROL_BG}" stroke="{COLOR_CONTROL}" stroke-width="1.00" />')
    lines.append(f'    <text x="98.00" y="97.00" font-family="{FONT_MONO}" font-size="10" font-weight="700" fill="{COLOR_CONTROL_LIGHT}" text-anchor="middle">CONTROL PLANE</text>')
    lines.append(f'    <text x="172.00" y="97.00" font-family="{FONT_SANS}" font-size="11" fill="{COLOR_TEXT_MUTED}">Out-of-band orchestration, cryptographic session management &amp; topology mesh discovery</text>')

    # 3 Control Plane Modules
    card_w = 312.00
    card_h = 76.00
    gap = 16.00
    start_x = 36.00
    card_y = 106.00

    # Module 1: PQ Hybrid Key-Derivation
    m1_x = start_x
    lines.append(f'    <rect x="{m1_x:.2f}" y="{card_y:.2f}" width="{card_w:.2f}" height="{card_h:.2f}" rx="6.00" fill="{COLOR_SUB_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="{m1_x + 12:.2f}" y="{card_y + 17:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">PQ Hybrid Handshake &amp; KDF</text>')
    lines.append(f'    <text x="{m1_x + 12:.2f}" y="{card_y + 33:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• ML-KEM-512 (FIPS 203) + X25519</text>')
    lines.append(f'    <text x="{m1_x + 12:.2f}" y="{card_y + 49:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Noise-IKpsk2 Token Sequencing</text>')
    lines.append(f'    <text x="{m1_x + 12:.2f}" y="{card_y + 65:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_CONTROL_LIGHT}">• Ephemeral Rekeying (120s Ratchet)</text>')

    # Module 2: Decentralized Threshold CA (yip-ca)
    m2_x = m1_x + card_w + gap
    lines.append(f'    <rect x="{m2_x:.2f}" y="{card_y:.2f}" width="{card_w:.2f}" height="{card_h:.2f}" rx="6.00" fill="{COLOR_SUB_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="{m2_x + 12:.2f}" y="{card_y + 17:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">Threshold CA Quorum <tspan fill="{COLOR_CONTROL_LIGHT}" font-family="{FONT_MONO}" font-size="11">(yip-ca)</tspan></text>')
    lines.append(f'    <text x="{m2_x + 12:.2f}" y="{card_y + 33:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• t-of-n FROST (RFC 9591) + ROAST</text>')
    lines.append(f'    <text x="{m2_x + 12:.2f}" y="{card_y + 49:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Byzantine Fault Tolerant Signers</text>')
    lines.append(f'    <text x="{m2_x + 12:.2f}" y="{card_y + 65:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_CONTROL_LIGHT}">• Proactive Refresh &amp; 70% TTL Renewal</text>')

    # Module 3: NAT Hole-Punching & Relay (yip-rendezvous)
    m3_x = m2_x + card_w + gap
    lines.append(f'    <rect x="{m3_x:.2f}" y="{card_y:.2f}" width="{card_w:.2f}" height="{card_h:.2f}" rx="6.00" fill="{COLOR_SUB_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="{m3_x + 12:.2f}" y="{card_y + 17:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">NAT Traversal &amp; Relay <tspan fill="{COLOR_CONTROL_LIGHT}" font-family="{FONT_MONO}" font-size="11">(yip-rendezvous)</tspan></text>')
    lines.append(f'    <text x="{m3_x + 12:.2f}" y="{card_y + 33:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• STUN/TURN Candidate Reflexive Probing</text>')
    lines.append(f'    <text x="{m3_x + 12:.2f}" y="{card_y + 49:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Symmetric NAT UDP Port Prediction</text>')
    lines.append(f'    <text x="{m3_x + 12:.2f}" y="{card_y + 65:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_CONTROL_LIGHT}">• Low-Latency Auto-Fallback Derp Relay</text>')
    lines.append('  </g>')

    # Connectors: Control Plane -> Data Plane
    lines.append('  <!-- Connectors: Control to Data Plane -->')
    lines.append('  <g id="connectors-control-to-data">')
    # Connector 1: Keys/Tokens from BLAKE2s to AEAD
    lines.append(f'    <path d="M 192.00 182.00 L 192.00 206.00 L 644.00 206.00 L 644.00 232.00" fill="none" stroke="{COLOR_CONTROL}" stroke-width="1.40" stroke-dasharray="3,3" marker-end="url(#arrow-ctrl)" />')
    lines.append(f'    <rect x="250.00" y="198.00" width="168.00" height="16.00" rx="3.00" fill="{COLOR_CANVAS_BG}" stroke="{COLOR_CONTROL}" stroke-width="0.80" />')
    lines.append(f'    <text x="334.00" y="210.00" font-family="{FONT_MONO}" font-size="9" font-weight="600" fill="{COLOR_CONTROL_LIGHT}" text-anchor="middle">Hybrid Keys &amp; Ratchet State</text>')

    # Connector 2: Topology / Peer routing from Mesh to SPSC Shards
    lines.append(f'    <path d="M 520.00 182.00 L 520.00 218.00 L 396.00 218.00 L 396.00 232.00" fill="none" stroke="{COLOR_CONTROL}" stroke-width="1.40" stroke-dasharray="3,3" marker-end="url(#arrow-ctrl)" />')
    lines.append(f'    <rect x="428.00" y="210.00" width="144.00" height="16.00" rx="3.00" fill="{COLOR_CANVAS_BG}" stroke="{COLOR_CONTROL}" stroke-width="0.80" />')
    lines.append(f'    <text x="500.00" y="222.00" font-family="{FONT_MONO}" font-size="9" font-weight="600" fill="{COLOR_CONTROL_LIGHT}" text-anchor="middle">Peer Routing &amp; Endpoints</text>')
    lines.append('  </g>')

    # =========================================================================
    # SECTION 2: MIDDLE DATA PLANE PIPELINE (#06b6d4)
    # =========================================================================
    lines.append('  <!-- ========================================================= -->')
    lines.append('  <!-- SECTION 2: DATA PLANE PIPELINE                           -->')
    lines.append('  <!-- ========================================================= -->')
    lines.append('  <g id="data-plane">')
    lines.append(f'    <rect x="24.00" y="236.00" width="992.00" height="168.00" rx="8.00" fill="url(#grad-data-card)" stroke="{COLOR_DATA}" stroke-width="1.20" stroke-opacity="0.70" />')

    # Section Header Pill with generous padding
    lines.append(f'    <rect x="36.00" y="246.00" width="164.00" height="18.00" rx="4.00" fill="{COLOR_DATA_BG}" stroke="{COLOR_DATA}" stroke-width="1.00" />')
    lines.append(f'    <text x="118.00" y="259.00" font-family="{FONT_MONO}" font-size="10" font-weight="700" fill="{COLOR_DATA_LIGHT}" text-anchor="middle">DATA PLANE PIPELINE</text>')
    lines.append(f'    <text x="212.00" y="259.00" font-family="{FONT_SANS}" font-size="11" fill="{COLOR_TEXT_MUTED}">Zero-lock ingress coalescing, ring buffer sharding, SIMD cryptography, and erasure coding</text>')

    # 4 Pipeline Stages
    d_card_w = 224.00
    d_card_h = 114.00
    d_gap = 24.00
    d_start_x = 36.00
    d_card_y = 278.00

    # Stage 1: Linux TUN/TAP Device
    s1_x = d_start_x
    lines.append(f'    <rect x="{s1_x:.2f}" y="{d_card_y:.2f}" width="{d_card_w:.2f}" height="{d_card_h:.2f}" rx="6.00" fill="{COLOR_SUB_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="{s1_x + 10:.2f}" y="{d_card_y + 16:.2f}" font-family="{FONT_MONO}" font-size="9" font-weight="700" fill="{COLOR_DATA_LIGHT}">STAGE 01 • INGRESS</text>')
    lines.append(f'    <text x="{s1_x + 10:.2f}" y="{d_card_y + 32:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">Linux TUN/TAP Device</text>')
    lines.append(f'    <text x="{s1_x + 10:.2f}" y="{d_card_y + 48:.2f}" font-family="{FONT_MONO}" font-size="10" font-weight="600" fill="{COLOR_DATA}">64KB GSO / GRO Coalescing</text>')
    lines.append(f'    <text x="{s1_x + 10:.2f}" y="{d_card_y + 68:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Multi-Queue kernel descriptors</text>')
    lines.append(f'    <text x="{s1_x + 10:.2f}" y="{d_card_y + 84:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Vectorized packet slicing</text>')
    lines.append(f'    <text x="{s1_x + 10:.2f}" y="{d_card_y + 100:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Zero-allocation page recycling</text>')

    # Inter-stage Arrow 1 -> 2
    a1_x1 = s1_x + d_card_w
    a1_x2 = a1_x1 + d_gap
    a1_y = d_card_y + d_card_h / 2
    lines.append(f'    <line x1="{a1_x1 + 3:.2f}" y1="{a1_y:.2f}" x2="{a1_x2 - 5:.2f}" y2="{a1_y:.2f}" stroke="{COLOR_DATA}" stroke-width="1.80" marker-end="url(#arrow-data)" />')

    # Stage 2: Lock-Free SPSC Shards
    s2_x = s1_x + d_card_w + d_gap
    lines.append(f'    <rect x="{s2_x:.2f}" y="{d_card_y:.2f}" width="{d_card_w:.2f}" height="{d_card_h:.2f}" rx="6.00" fill="{COLOR_SUB_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="{s2_x + 10:.2f}" y="{d_card_y + 16:.2f}" font-family="{FONT_MONO}" font-size="9" font-weight="700" fill="{COLOR_DATA_LIGHT}">STAGE 02 • SHARDING</text>')
    lines.append(f'    <text x="{s2_x + 10:.2f}" y="{d_card_y + 32:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">Lock-Free SPSC Shards</text>')
    lines.append(f'    <text x="{s2_x + 10:.2f}" y="{d_card_y + 48:.2f}" font-family="{FONT_MONO}" font-size="10" font-weight="600" fill="{COLOR_DATA}">Shard 0 .. Shard N Rings</text>')
    lines.append(f'    <text x="{s2_x + 10:.2f}" y="{d_card_y + 68:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• 128-byte cacheline isolation</text>')
    lines.append(f'    <text x="{s2_x + 10:.2f}" y="{d_card_y + 84:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Dedicated core pinning &amp; affinity</text>')
    lines.append(f'    <text x="{s2_x + 10:.2f}" y="{d_card_y + 100:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• 0 lock contention across cores</text>')

    # Inter-stage Arrow 2 -> 3
    a2_x1 = s2_x + d_card_w
    a2_x2 = a2_x1 + d_gap
    lines.append(f'    <line x1="{a2_x1 + 3:.2f}" y1="{a1_y:.2f}" x2="{a2_x2 - 5:.2f}" y2="{a1_y:.2f}" stroke="{COLOR_DATA}" stroke-width="1.80" marker-end="url(#arrow-data)" />')

    # Stage 3: ChaCha20-Poly1305 AEAD
    s3_x = s2_x + d_card_w + d_gap
    lines.append(f'    <rect x="{s3_x:.2f}" y="{d_card_y:.2f}" width="{d_card_w:.2f}" height="{d_card_h:.2f}" rx="6.00" fill="{COLOR_SUB_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="{s3_x + 10:.2f}" y="{d_card_y + 16:.2f}" font-family="{FONT_MONO}" font-size="9" font-weight="700" fill="{COLOR_DATA_LIGHT}">STAGE 03 • CRYPTO</text>')
    lines.append(f'    <text x="{s3_x + 10:.2f}" y="{d_card_y + 32:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">ChaCha20-Poly1305 AEAD</text>')
    lines.append(f'    <text x="{s3_x + 10:.2f}" y="{d_card_y + 48:.2f}" font-family="{FONT_MONO}" font-size="10" font-weight="600" fill="{COLOR_DATA}">Noise-IKpsk2 • 120s Ratchet</text>')
    lines.append(f'    <text x="{s3_x + 10:.2f}" y="{d_card_y + 68:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• AVX2 / NEON SIMD acceleration</text>')
    lines.append(f'    <text x="{s3_x + 10:.2f}" y="{d_card_y + 84:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Bitmap sliding replay window</text>')
    lines.append(f'    <text x="{s3_x + 10:.2f}" y="{d_card_y + 100:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• WireGuard-compatible framing</text>')

    # Inter-stage Arrow 3 -> 4
    a3_x1 = s3_x + d_card_w
    a3_x2 = a3_x1 + d_gap
    lines.append(f'    <line x1="{a3_x1 + 3:.2f}" y1="{a1_y:.2f}" x2="{a3_x2 - 5:.2f}" y2="{a1_y:.2f}" stroke="{COLOR_FEC}" stroke-width="1.80" marker-end="url(#arrow-fec)" />')

    # Stage 4: Systematic Cauchy RS-FEC (#f97316 Hero Accent!)
    s4_x = s3_x + d_card_w + d_gap
    lines.append(f'    <rect x="{s4_x:.2f}" y="{d_card_y:.2f}" width="{d_card_w:.2f}" height="{d_card_h:.2f}" rx="6.00" fill="url(#grad-fec-subcard)" stroke="{COLOR_FEC}" stroke-width="1.40" />')
    lines.append(f'    <text x="{s4_x + 10:.2f}" y="{d_card_y + 16:.2f}" font-family="{FONT_MONO}" font-size="9" font-weight="700" fill="{COLOR_FEC_LIGHT}">STAGE 04 • LOSS RECOVERY</text>')
    lines.append(f'    <text x="{s4_x + 10:.2f}" y="{d_card_y + 32:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">Systematic Cauchy RS-FEC</text>')
    lines.append(f'    <text x="{s4_x + 10:.2f}" y="{d_card_y + 48:.2f}" font-family="{FONT_MONO}" font-size="10" font-weight="600" fill="{COLOR_FEC}">GF(256) SIMD + RLNC</text>')
    lines.append(f'    <text x="{s4_x + 10:.2f}" y="{d_card_y + 68:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_WHITE}">• Systematic Cauchy generator</text>')
    lines.append(f'    <text x="{s4_x + 10:.2f}" y="{d_card_y + 84:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_WHITE}">• Random Linear Network Coding</text>')
    lines.append(f'    <text x="{s4_x + 10:.2f}" y="{d_card_y + 100:.2f}" font-family="{FONT_SANS}" font-size="10.5" font-weight="600" fill="{COLOR_FEC_LIGHT}">• 0-RTT Recovery up to 30% loss</text>')
    lines.append('  </g>')

    # =========================================================================
    # DUAL-PATH ROUTER / BRANCHING DISPATCH
    # Distinct vertical tiers to eliminate line intersections & text collisions:
    #   Tier 1 (y=412): Trunk line from RS-FEC (x=892) left to router top (x=520)
    #   Tier 2 (y=422-446): Dynamic Transport Router Node & Fork Badges
    #   Tier 3 (y=434-460): Fork lines to Fast Path (x=266) & Stealth Path (x=774)
    # =========================================================================
    lines.append('  <!-- Routing Dispatch -->')
    lines.append('  <g id="dual-path-dispatch">')

    # Dispatcher Node (Centered horizontally at x=520, y=422)
    disp_x = 390.00
    disp_y = 422.00
    disp_w = 260.00
    disp_h = 24.00

    # Trunk from RS-FEC (x=892) down to y=412, left to x=520, entering top of Router
    lines.append(f'    <path d="M 892.00 392.00 L 892.00 412.00 L 520.00 412.00 L 520.00 {disp_y:.2f}" fill="none" stroke="{COLOR_FEC}" stroke-width="1.60" marker-end="url(#arrow-fec)" />')

    # Router Card Box
    lines.append(f'    <rect x="{disp_x:.2f}" y="{disp_y:.2f}" width="{disp_w:.2f}" height="{disp_h:.2f}" rx="5.00" fill="{COLOR_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.20" />')
    # Vector branch arrow icon
    lines.append(f'    <path d="M 404.00,434.00 L 413.00,434.00 M 413.00,434.00 L 417.00,430.00 M 413.00,434.00 L 417.00,438.00" fill="none" stroke="{COLOR_TEXT_WHITE}" stroke-width="1.50" stroke-linecap="round" />')
    lines.append(f'    <text x="528.00" y="438.00" font-family="{FONT_MONO}" font-size="10" font-weight="700" fill="{COLOR_TEXT_WHITE}" text-anchor="middle">DYNAMIC TRANSPORT ROUTER</text>')

    # Fork 1: Dispatcher Left to Fast Path (leaves router left at x=390, y=434 -> drops into Fast Path at x=266, y=460)
    lines.append(f'    <path d="M {disp_x:.2f} 434.00 L 266.00 434.00 L 266.00 460.00" fill="none" stroke="{COLOR_FAST}" stroke-width="1.60" marker-end="url(#arrow-fast)" />')
    lines.append(f'    <rect x="254.00" y="425.00" width="124.00" height="18.00" rx="3.00" fill="{COLOR_CANVAS_BG}" stroke="{COLOR_FAST}" stroke-width="0.80" />')
    lines.append(f'    <text x="316.00" y="437.00" font-family="{FONT_SANS}" font-size="9" font-weight="600" fill="{COLOR_FAST_LIGHT}" text-anchor="middle">High-Throughput DC/WAN</text>')

    # Fork 2: Dispatcher Right to Stealth Path (leaves router right at x=650, y=434 -> drops into Stealth Path at x=774, y=460)
    lines.append(f'    <path d="M {disp_x + disp_w:.2f} 434.00 L 774.00 434.00 L 774.00 460.00" fill="none" stroke="{COLOR_STEALTH}" stroke-width="1.60" marker-end="url(#arrow-stealth)" />')
    lines.append(f'    <rect x="662.00" y="425.00" width="112.00" height="18.00" rx="3.00" fill="{COLOR_CANVAS_BG}" stroke="{COLOR_STEALTH}" stroke-width="0.80" />')
    lines.append(f'    <text x="718.00" y="437.00" font-family="{FONT_SANS}" font-size="9" font-weight="600" fill="{COLOR_STEALTH_LIGHT}" text-anchor="middle">Adversarial / DPI</text>')
    lines.append('  </g>')

    # =========================================================================
    # SECTION 3: BOTTOM DUAL-PATH SUBSYSTEMS
    # =========================================================================
    lines.append('  <!-- ========================================================= -->')
    lines.append('  <!-- SECTION 3: DUAL-PATH SUBSYSTEMS                          -->')
    lines.append('  <!-- ========================================================= -->')
    bottom_y = 464.00
    bottom_h = 210.00
    bottom_w = 484.00

    # -------------------------------------------------------------------------
    # PATH A: FAST PATH (#10b981)
    # -------------------------------------------------------------------------
    fp_x = 24.00
    lines.append('  <g id="fast-path">')
    lines.append(f'    <rect x="{fp_x:.2f}" y="{bottom_y:.2f}" width="{bottom_w:.2f}" height="{bottom_h:.2f}" rx="8.00" fill="url(#grad-fast-card)" stroke="{COLOR_FAST}" stroke-width="1.30" stroke-opacity="0.80" />')

    # Header Pill with generous padding
    lines.append(f'    <rect x="{fp_x + 12:.2f}" y="{bottom_y + 12:.2f}" width="196.00" height="18.00" rx="4.00" fill="{COLOR_FAST_BG}" stroke="{COLOR_FAST}" stroke-width="1.00" />')
    lines.append(f'    <text x="{fp_x + 110:.2f}" y="{bottom_y + 25:.2f}" font-family="{FONT_MONO}" font-size="10" font-weight="700" fill="{COLOR_FAST_LIGHT}" text-anchor="middle">FAST PATH • KERNEL BYPASS</text>')
    lines.append(f'    <text x="{fp_x + 220:.2f}" y="{bottom_y + 25:.2f}" font-family="{FONT_SANS}" font-size="11" fill="{COLOR_TEXT_MUTED}">Hardware-accelerated line-rate zero-copy</text>')

    # Inner Card 1: eBPF AF_XDP Zero-Copy (XSKMAP)
    ic1_y = bottom_y + 38.00
    ic1_h = 58.00
    ic1_w = bottom_w - 24.00
    lines.append(f'    <rect x="{fp_x + 12:.2f}" y="{ic1_y:.2f}" width="{ic1_w:.2f}" height="{ic1_h:.2f}" rx="6.00" fill="{COLOR_SUB_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="{fp_x + 22:.2f}" y="{ic1_y + 18:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">eBPF AF_XDP Zero-Copy <tspan fill="{COLOR_FAST_LIGHT}" font-family="{FONT_MONO}" font-size="11">(XSKMAP)</tspan></text>')
    lines.append(f'    <text x="{fp_x + 22:.2f}" y="{ic1_y + 34:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Direct NIC DMA via UMEM Fill &amp; Completion rings</text>')
    lines.append(f'    <text x="{fp_x + 22:.2f}" y="{ic1_y + 50:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Bypass Linux netfilter, SKB allocation &amp; routing stack</text>')

    # Inner Card 2: Vectorized epoll sendmmsg
    ic2_y = ic1_y + ic1_h + 8.00
    lines.append(f'    <rect x="{fp_x + 12:.2f}" y="{ic2_y:.2f}" width="{ic1_w:.2f}" height="{ic1_h:.2f}" rx="6.00" fill="{COLOR_SUB_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="{fp_x + 22:.2f}" y="{ic2_y + 18:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">Vectorized epoll sendmmsg / recvmmsg</text>')
    lines.append(f'    <text x="{fp_x + 22:.2f}" y="{ic2_y + 34:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• 1024-packet batch descriptor submission per syscall</text>')
    lines.append(f'    <text x="{fp_x + 22:.2f}" y="{ic2_y + 50:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Edge-triggered vector notification with 0 jitter</text>')

    # Outcome Banner: 40+ Gbps (Vector lightning bolt)
    out1_y = ic2_y + ic1_h + 8.00
    out1_h = 32.00
    lines.append(f'    <rect x="{fp_x + 12:.2f}" y="{out1_y:.2f}" width="{ic1_w:.2f}" height="{out1_h:.2f}" rx="6.00" fill="{COLOR_FAST_BG}" stroke="{COLOR_FAST}" stroke-width="1.20" />')
    lines.append(f'    <polygon points="{fp_x + 36:.2f},{out1_y + 9:.2f} {fp_x + 29:.2f},{out1_y + 17:.2f} {fp_x + 35:.2f},{out1_y + 17:.2f} {fp_x + 32:.2f},{out1_y + 24:.2f} {fp_x + 42:.2f},{out1_y + 14:.2f} {fp_x + 36:.2f},{out1_y + 14:.2f}" fill="{COLOR_FAST_LIGHT}" />')
    lines.append(f'    <text x="{fp_x + bottom_w / 2 + 10:.2f}" y="{out1_y + 20:.2f}" font-family="{FONT_MONO}" font-size="10" font-weight="700" fill="{COLOR_FAST_LIGHT}" text-anchor="middle">40+ Gbps Line-Rate • 8.2M pps (16-Core AF_XDP Zero-Copy)</text>')
    lines.append('  </g>')

    # -------------------------------------------------------------------------
    # PATH B: STEALTH / ANTI-DPI PATH (#e11d48 / #f97316)
    # -------------------------------------------------------------------------
    sp_x = fp_x + bottom_w + 24.00
    lines.append('  <g id="stealth-path">')
    lines.append(f'    <rect x="{sp_x:.2f}" y="{bottom_y:.2f}" width="{bottom_w:.2f}" height="{bottom_h:.2f}" rx="8.00" fill="url(#grad-stealth-card)" stroke="{COLOR_STEALTH}" stroke-width="1.30" stroke-opacity="0.80" />')

    # Header Pill with generous padding
    lines.append(f'    <rect x="{sp_x + 12:.2f}" y="{bottom_y + 12:.2f}" width="224.00" height="18.00" rx="4.00" fill="{COLOR_STEALTH_BG}" stroke="{COLOR_STEALTH}" stroke-width="1.00" />')
    lines.append(f'    <text x="{sp_x + 124:.2f}" y="{bottom_y + 25:.2f}" font-family="{FONT_MONO}" font-size="10" font-weight="700" fill="{COLOR_STEALTH_LIGHT}" text-anchor="middle">STEALTH • ANTI-DPI CAMOUFLAGE</text>')
    lines.append(f'    <text x="{sp_x + 248:.2f}" y="{bottom_y + 25:.2f}" font-family="{FONT_SANS}" font-size="11" fill="{COLOR_TEXT_MUTED}">Adversarial censorship &amp; DPI bypass</text>')

    # Inner Card 1: uTLS Chrome JA3/JA4 Parity
    sc1_y = bottom_y + 38.00
    sc1_h = 58.00
    sc1_w = bottom_w - 24.00
    lines.append(f'    <rect x="{sp_x + 12:.2f}" y="{sc1_y:.2f}" width="{sc1_w:.2f}" height="{sc1_h:.2f}" rx="6.00" fill="{COLOR_SUB_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="{sp_x + 22:.2f}" y="{sc1_y + 18:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">uTLS Chrome JA3/JA4 Parity</text>')
    lines.append(f'    <text x="{sp_x + 22:.2f}" y="{sc1_y + 34:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Exact TLS fingerprint emulation (Chrome 120-130)</text>')
    lines.append(f'    <text x="{sp_x + 22:.2f}" y="{sc1_y + 50:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Permuted cipher suites, GREASE, extensions &amp; ALPN</text>')

    # Inner Card 2: Xray-REALITY TLS 1.3 / QUIC
    sc2_y = sc1_y + sc1_h + 8.00
    lines.append(f'    <rect x="{sp_x + 12:.2f}" y="{sc2_y:.2f}" width="{sc1_w:.2f}" height="{sc1_h:.2f}" rx="6.00" fill="{COLOR_SUB_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="{sp_x + 22:.2f}" y="{sc2_y + 18:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">Xray-REALITY TLS 1.3 / QUIC</text>')
    lines.append(f'    <text x="{sp_x + 22:.2f}" y="{sc2_y + 34:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Server Name Indication (SNI) authentic certificate borrowing</text>')
    lines.append(f'    <text x="{sp_x + 22:.2f}" y="{sc2_y + 50:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Active probe rejection with transparent upstream proxying</text>')

    # Outcome Banner: 4-Engine DPI Oracle Pass (Vector shield)
    lines.append(f'    <rect x="{sp_x + 12:.2f}" y="{out1_y:.2f}" width="{sc1_w:.2f}" height="{out1_h:.2f}" rx="6.00" fill="{COLOR_STEALTH_BG}" stroke="{COLOR_STEALTH}" stroke-width="1.20" />')
    lines.append(f'    <path d="M {sp_x + 32:.2f},{out1_y + 10:.2f} L {sp_x + 38:.2f},{out1_y + 8:.2f} L {sp_x + 44:.2f},{out1_y + 10:.2f} L {sp_x + 44:.2f},{out1_y + 16:.2f} C {sp_x + 44:.2f},{out1_y + 21:.2f} {sp_x + 38:.2f},{out1_y + 24:.2f} {sp_x + 38:.2f},{out1_y + 24:.2f} C {sp_x + 38:.2f},{out1_y + 24:.2f} {sp_x + 32:.2f},{out1_y + 21:.2f} {sp_x + 32:.2f},{out1_y + 16:.2f} Z" fill="{COLOR_STEALTH_LIGHT}" />')
    lines.append(f'    <text x="{sp_x + bottom_w / 2 + 10:.2f}" y="{out1_y + 20:.2f}" font-family="{FONT_MONO}" font-size="10" font-weight="700" fill="{COLOR_STEALTH_LIGHT}" text-anchor="middle">4-ENGINE DPI ORACLE: nDPI • Zeek • Suricata • Wireshark</text>')
    lines.append('  </g>')

    # =========================================================================
    # FOOTER BAR
    # =========================================================================
    lines.append('  <!-- Footer Bar -->')
    lines.append('  <g id="footer">')
    lines.append(f'    <line x1="24.00" y1="688.00" x2="{w - 24:.2f}" y2="688.00" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="28.00" y="708.00" font-family="{FONT_MONO}" font-size="10.5" fill="{COLOR_TEXT_DIM}">Target: Linux x86_64 / aarch64 • AVX2 / AVX-512 / ARM NEON • Rust 2024 Edition</text>')
    lines.append(f'    <text x="{w - 28:.2f}" y="708.00" font-family="{FONT_MONO}" font-size="10.5" fill="{COLOR_TEXT_DIM}" text-anchor="end">Deterministic Vector Architecture • github.com/femboyisp/yip</text>')
    lines.append('  </g>')

    lines.append('</svg>')
    return "\n".join(lines) + "\n"


def rasterize_svg_to_png(svg_path: Path, png_path: Path, density: int = 192) -> bool:
    for cmd in ["magick", "convert"]:
        try:
            subprocess.run([cmd, "-density", str(density), str(svg_path), str(png_path)],
                           check=True, capture_output=True)
            if png_path.exists() and png_path.stat().st_size > 0:
                print(f"Rasterized: {png_path} ({png_path.stat().st_size / 1024:.1f} KB)")
                return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return False


def main():
    parser = argparse.ArgumentParser(description="Deterministic SVG system architecture diagram generator.")
    parser.add_argument("--output", type=Path, default=None,
                        help="Path to output SVG file (defaults to assets/architecture.svg).")
    parser.add_argument("--check", action="store_true",
                        help="Check if SVG asset is up-to-date and valid XML without writing to disk.")
    parser.add_argument("--repo-root", type=Path, default=None,
                        help="Path to repository root (defaults to auto-detection).")
    args = parser.parse_args()

    if args.repo_root:
        repo_root = args.repo_root.resolve()
    else:
        repo_root = Path(__file__).resolve().parent.parent.parent

    target_path = args.output.resolve() if args.output else (repo_root / "assets" / "architecture.svg")

    svg_content = build_architecture_svg()

    # Validate XML
    try:
        ET.fromstring(svg_content)
    except ET.ParseError as e:
        print(f"Error: Generated SVG is not valid XML: {e}", file=sys.stderr)
        sys.exit(1)

    if args.check:
        if not target_path.exists():
            print(f"Check failed: {target_path} does not exist on disk", file=sys.stderr)
            sys.exit(1)

        try:
            disk_content = target_path.read_text(encoding="utf-8")
            ET.fromstring(disk_content)
        except Exception as e:
            print(f"Check failed: {target_path} is not valid XML on disk: {e}", file=sys.stderr)
            sys.exit(1)

        if disk_content != svg_content:
            print(f"Check failed: {target_path} differs from generated output (drift detected)", file=sys.stderr)
            sys.exit(1)

        print(f"OK: {target_path.name} is up-to-date and valid XML.")
        sys.exit(0)

    # Generation mode
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(svg_content, encoding="utf-8")
    print(f"Generated: {target_path} ({len(svg_content)} bytes)")

    # Rasterize PNG
    png_path = target_path.with_suffix(".png")
    rasterize_svg_to_png(target_path, png_path)


if __name__ == "__main__":
    main()
