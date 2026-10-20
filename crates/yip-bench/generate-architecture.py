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

from pathlib import Path
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
    h = 720
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
    # Engine Logo Badge
    lines.append(f'    <rect x="24.00" y="20.00" width="76.00" height="24.00" rx="6.00" fill="{COLOR_FEC_BG}" stroke="{COLOR_FEC}" stroke-width="1.00" />')
    lines.append(f'    <text x="62.00" y="36.00" font-family="{FONT_MONO}" font-size="11" font-weight="700" fill="{COLOR_FEC_LIGHT}" text-anchor="middle">🦊 YIP</text>')
    
    # Title & Subtitle
    lines.append(f'    <text x="110.00" y="37.00" font-family="{FONT_SANS}" font-size="17" font-weight="700" fill="{COLOR_TEXT_WHITE}">DUAL-PATH SYSTEM ARCHITECTURE</text>')
    lines.append(f'    <text x="110.00" y="55.00" font-family="{FONT_SANS}" font-size="11.5" fill="{COLOR_TEXT_MUTED}">Zero-Lock Core Pipeline • eBPF AF_XDP Line-Rate Bypass &amp; uTLS / Xray-REALITY Anti-DPI Subsystems</text>')

    # Feature Badges on right
    badges = [
        ("40+ Gbps eBPF", COLOR_FAST_BG, COLOR_FAST_LIGHT, COLOR_FAST),
        ("GF(256) RS-FEC", COLOR_FEC_BG, COLOR_FEC_LIGHT, COLOR_FEC),
        ("Noise-IK AEAD", COLOR_CONTROL_BG, COLOR_CONTROL_LIGHT, COLOR_CONTROL),
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
    
    # Section Header
    lines.append(f'    <rect x="36.00" y="84.00" width="112.00" height="18.00" rx="4.00" fill="{COLOR_CONTROL_BG}" stroke="{COLOR_CONTROL}" stroke-width="1.00" />')
    lines.append(f'    <text x="92.00" y="97.00" font-family="{FONT_MONO}" font-size="10" font-weight="700" fill="{COLOR_CONTROL_LIGHT}" text-anchor="middle">CONTROL PLANE</text>')
    lines.append(f'    <text x="156.00" y="97.00" font-family="{FONT_SANS}" font-size="11" fill="{COLOR_TEXT_MUTED}">Out-of-band orchestration, cryptographic session management &amp; topology mesh discovery</text>')

    # 3 Control Plane Modules
    card_w = 312.00
    card_h = 74.00
    gap = 16.00
    start_x = 36.00
    card_y = 108.00

    # Module 1: BLAKE2s Key-Derivation
    m1_x = start_x
    lines.append(f'    <rect x="{m1_x:.2f}" y="{card_y:.2f}" width="{card_w:.2f}" height="{card_h:.2f}" rx="6.00" fill="{COLOR_SUB_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="{m1_x + 12:.2f}" y="{card_y + 18:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">BLAKE2s Key-Derivation</text>')
    lines.append(f'    <text x="{m1_x + 12:.2f}" y="{card_y + 35:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Static &amp; Ephemeral 256-bit Keypairs</text>')
    lines.append(f'    <text x="{m1_x + 12:.2f}" y="{card_y + 51:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Noise-IK Handshake Token Generation</text>')
    lines.append(f'    <text x="{m1_x + 12:.2f}" y="{card_y + 67:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_CONTROL_LIGHT}">• Ephemeral Rekeying State (120s Ratchet)</text>')

    # Module 2: CA-Gated Mesh Discovery (yip-ca)
    m2_x = m1_x + card_w + gap
    lines.append(f'    <rect x="{m2_x:.2f}" y="{card_y:.2f}" width="{card_w:.2f}" height="{card_h:.2f}" rx="6.00" fill="{COLOR_SUB_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="{m2_x + 12:.2f}" y="{card_y + 18:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">CA-Gated Mesh Discovery <tspan fill="{COLOR_CONTROL_LIGHT}" font-family="{FONT_MONO}" font-size="11">(yip-ca)</tspan></text>')
    lines.append(f'    <text x="{m2_x + 12:.2f}" y="{card_y + 35:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• mTLS Node Identity &amp; Role Claims</text>')
    lines.append(f'    <text x="{m2_x + 12:.2f}" y="{card_y + 51:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Gossip Membership &amp; Dynamic Topology</text>')
    lines.append(f'    <text x="{m2_x + 12:.2f}" y="{card_y + 67:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_CONTROL_LIGHT}">• Cryptographic Access Control List (ACL)</text>')

    # Module 3: NAT Hole-Punching & Relay (yip-rendezvous)
    m3_x = m2_x + card_w + gap
    lines.append(f'    <rect x="{m3_x:.2f}" y="{card_y:.2f}" width="{card_w:.2f}" height="{card_h:.2f}" rx="6.00" fill="{COLOR_SUB_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="{m3_x + 12:.2f}" y="{card_y + 18:.2f}" font-family="{FONT_SANS}" font-size="12" font-weight="700" fill="{COLOR_TEXT_WHITE}">NAT Traversal &amp; Relay <tspan fill="{COLOR_CONTROL_LIGHT}" font-family="{FONT_MONO}" font-size="11">(yip-rendezvous)</tspan></text>')
    lines.append(f'    <text x="{m3_x + 12:.2f}" y="{card_y + 35:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• STUN/TURN Candidate Reflexive Probing</text>')
    lines.append(f'    <text x="{m3_x + 12:.2f}" y="{card_y + 51:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_TEXT_MUTED}">• Symmetric NAT UDP Port Prediction</text>')
    lines.append(f'    <text x="{m3_x + 12:.2f}" y="{card_y + 67:.2f}" font-family="{FONT_SANS}" font-size="10.5" fill="{COLOR_CONTROL_LIGHT}">• Low-Latency Auto-Fallback Derp Relay</text>')
    lines.append('  </g>')

    # Connectors: Control Plane -> Data Plane
    lines.append('  <!-- Connectors: Control to Data Plane -->')
    lines.append('  <g id="connectors-control-to-data">')
    # Connector 1: Keys/Tokens from BLAKE2s to AEAD
    lines.append(f'    <path d="M 192.00 182.00 L 192.00 206.00 L 644.00 206.00 L 644.00 232.00" fill="none" stroke="{COLOR_CONTROL}" stroke-width="1.40" stroke-dasharray="3,3" marker-end="url(#arrow-ctrl)" />')
    lines.append(f'    <rect x="250.00" y="198.00" width="168.00" height="16.00" rx="3.00" fill="{COLOR_CANVAS_BG}" stroke="{COLOR_CONTROL}" stroke-width="0.80" />')
    lines.append(f'    <text x="334.00" y="210.00" font-family="{FONT_MONO}" font-size="9" font-weight="600" fill="{COLOR_CONTROL_LIGHT}" text-anchor="middle">Noise Keys &amp; Ratchet State</text>')

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

    # Section Header
    lines.append(f'    <rect x="36.00" y="246.00" width="138.00" height="18.00" rx="4.00" fill="{COLOR_DATA_BG}" stroke="{COLOR_DATA}" stroke-width="1.00" />')
    lines.append(f'    <text x="105.00" y="259.00" font-family="{FONT_MONO}" font-size="10" font-weight="700" fill="{COLOR_DATA_LIGHT}" text-anchor="middle">DATA PLANE PIPELINE</text>')
    lines.append(f'    <text x="182.00" y="259.00" font-family="{FONT_SANS}" font-size="11" fill="{COLOR_TEXT_MUTED}">Zero-lock ingress coalescing, ring buffer sharding, SIMD cryptography, and erasure coding</text>')

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
    lines.append(f'    <text x="{s3_x + 10:.2f}" y="{d_card_y + 48:.2f}" font-family="{FONT_MONO}" font-size="10" font-weight="600" fill="{COLOR_DATA}">Noise-IK • 120s Ratchet</text>')
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
    # =========================================================================
    lines.append('  <!-- Routing Dispatch -->')
    lines.append('  <g id="dual-path-dispatch">')
    # Trunk from RS-FEC (x=892) down to y=417, then left to Dispatcher node right edge
    lines.append(f'    <path d="M 892.00 392.00 L 892.00 417.00 L 640.00 417.00" fill="none" stroke="{COLOR_FEC}" stroke-width="1.60" marker-end="url(#arrow-fec)" />')
    
    # Dispatcher Node (Centered)
    disp_x = 390.00
    disp_y = 405.00
    disp_w = 250.00
    disp_h = 24.00
    lines.append(f'    <rect x="{disp_x:.2f}" y="{disp_y:.2f}" width="{disp_w:.2f}" height="{disp_h:.2f}" rx="5.00" fill="{COLOR_CARD_BG}" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.20" />')
    lines.append(f'    <text x="{disp_x + disp_w / 2:.2f}" y="{disp_y + 16.00:.2f}" font-family="{FONT_MONO}" font-size="10" font-weight="700" fill="{COLOR_TEXT_WHITE}" text-anchor="middle">🔀 DYNAMIC TRANSPORT ROUTER</text>')

    # Fork 1: Dispatcher Left to Fast Path
    lines.append(f'    <path d="M {disp_x:.2f} {disp_y + disp_h / 2:.2f} L 266.00 {disp_y + disp_h / 2:.2f} L 266.00 446.00" fill="none" stroke="{COLOR_FAST}" stroke-width="1.60" marker-end="url(#arrow-fast)" />')
    lines.append(f'    <text x="328.00" y="413.00" font-family="{FONT_SANS}" font-size="9" font-weight="600" fill="{COLOR_FAST_LIGHT}" text-anchor="middle">High-Throughput DC/WAN</text>')

    # Fork 2: Dispatcher Right to Stealth Path
    lines.append(f'    <path d="M {disp_x + disp_w:.2f} {disp_y + disp_h / 2:.2f} L 774.00 {disp_y + disp_h / 2:.2f} L 774.00 446.00" fill="none" stroke="{COLOR_STEALTH}" stroke-width="1.60" marker-end="url(#arrow-stealth)" />')
    lines.append(f'    <text x="708.00" y="413.00" font-family="{FONT_SANS}" font-size="9" font-weight="600" fill="{COLOR_STEALTH_LIGHT}" text-anchor="middle">Adversarial / DPI Networks</text>')
    lines.append('  </g>')

    # =========================================================================
    # SECTION 3: BOTTOM DUAL-PATH SUBSYSTEMS
    # =========================================================================
    lines.append('  <!-- ========================================================= -->')
    lines.append('  <!-- SECTION 3: DUAL-PATH SUBSYSTEMS                          -->')
    lines.append('  <!-- ========================================================= -->')
    bottom_y = 450.00
    bottom_h = 210.00
    bottom_w = 484.00

    # -------------------------------------------------------------------------
    # PATH A: FAST PATH (#10b981)
    # -------------------------------------------------------------------------
    fp_x = 24.00
    lines.append('  <g id="fast-path">')
    lines.append(f'    <rect x="{fp_x:.2f}" y="{bottom_y:.2f}" width="{bottom_w:.2f}" height="{bottom_h:.2f}" rx="8.00" fill="url(#grad-fast-card)" stroke="{COLOR_FAST}" stroke-width="1.30" stroke-opacity="0.80" />')
    
    # Header
    lines.append(f'    <rect x="{fp_x + 12:.2f}" y="{bottom_y + 12:.2f}" width="168.00" height="18.00" rx="4.00" fill="{COLOR_FAST_BG}" stroke="{COLOR_FAST}" stroke-width="1.00" />')
    lines.append(f'    <text x="{fp_x + 96:.2f}" y="{bottom_y + 25:.2f}" font-family="{FONT_MONO}" font-size="10" font-weight="700" fill="{COLOR_FAST_LIGHT}" text-anchor="middle">FAST PATH • KERNEL BYPASS</text>')
    lines.append(f'    <text x="{fp_x + 190:.2f}" y="{bottom_y + 25:.2f}" font-family="{FONT_SANS}" font-size="11" fill="{COLOR_TEXT_MUTED}">Hardware-accelerated line-rate zero-copy</text>')

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

    # Outcome Banner: 40+ Gbps
    out1_y = ic2_y + ic1_h + 8.00
    out1_h = 32.00
    lines.append(f'    <rect x="{fp_x + 12:.2f}" y="{out1_y:.2f}" width="{ic1_w:.2f}" height="{out1_h:.2f}" rx="6.00" fill="{COLOR_FAST_BG}" stroke="{COLOR_FAST}" stroke-width="1.20" />')
    lines.append(f'    <text x="{fp_x + bottom_w / 2:.2f}" y="{out1_y + 20:.2f}" font-family="{FONT_MONO}" font-size="11.5" font-weight="700" fill="{COLOR_FAST_LIGHT}" text-anchor="middle">⚡ PERFORMANCE: 40+ Gbps Line-Rate • 8.2M pps (16-Core AF_XDP)</text>')
    lines.append('  </g>')

    # -------------------------------------------------------------------------
    # PATH B: STEALTH / ANTI-DPI PATH (#e11d48 / #f97316)
    # -------------------------------------------------------------------------
    sp_x = fp_x + bottom_w + 24.00
    lines.append('  <g id="stealth-path">')
    lines.append(f'    <rect x="{sp_x:.2f}" y="{bottom_y:.2f}" width="{bottom_w:.2f}" height="{bottom_h:.2f}" rx="8.00" fill="url(#grad-stealth-card)" stroke="{COLOR_STEALTH}" stroke-width="1.30" stroke-opacity="0.80" />')

    # Header
    lines.append(f'    <rect x="{sp_x + 12:.2f}" y="{bottom_y + 12:.2f}" width="168.00" height="18.00" rx="4.00" fill="{COLOR_STEALTH_BG}" stroke="{COLOR_STEALTH}" stroke-width="1.00" />')
    lines.append(f'    <text x="{sp_x + 96:.2f}" y="{bottom_y + 25:.2f}" font-family="{FONT_MONO}" font-size="10" font-weight="700" fill="{COLOR_STEALTH_LIGHT}" text-anchor="middle">STEALTH • ANTI-DPI CAMOUFLAGE</text>')
    lines.append(f'    <text x="{sp_x + 190:.2f}" y="{bottom_y + 25:.2f}" font-family="{FONT_SANS}" font-size="11" fill="{COLOR_TEXT_MUTED}">Adversarial censorship &amp; stateful firewall bypass</text>')

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

    # Outcome Banner: 4-Engine DPI Oracle Pass
    lines.append(f'    <rect x="{sp_x + 12:.2f}" y="{out1_y:.2f}" width="{sc1_w:.2f}" height="{out1_h:.2f}" rx="6.00" fill="{COLOR_STEALTH_BG}" stroke="{COLOR_STEALTH}" stroke-width="1.20" />')
    lines.append(f'    <text x="{sp_x + bottom_w / 2:.2f}" y="{out1_y + 20:.2f}" font-family="{FONT_MONO}" font-size="11.5" font-weight="700" fill="{COLOR_STEALTH_LIGHT}" text-anchor="middle">🛡️ 4-ENGINE DPI ORACLE IMMUNE: nDPI • Zeek • Suricata • Wireshark</text>')
    lines.append('  </g>')

    # =========================================================================
    # FOOTER BAR
    # =========================================================================
    lines.append('  <!-- Footer Bar -->')
    lines.append('  <g id="footer">')
    lines.append(f'    <line x1="24.00" y1="672.00" x2="{w - 24:.2f}" y2="672.00" stroke="{COLOR_CANVAS_BORDER}" stroke-width="1.00" />')
    lines.append(f'    <text x="28.00" y="692.00" font-family="{FONT_MONO}" font-size="10.5" fill="{COLOR_TEXT_DIM}">Target: Linux x86_64 / aarch64 • AVX2 / AVX-512 / ARM NEON • Rust 2024 Edition</text>')
    lines.append(f'    <text x="{w - 28:.2f}" y="692.00" font-family="{FONT_MONO}" font-size="10.5" fill="{COLOR_TEXT_DIM}" text-anchor="end">Deterministic Vector Architecture • github.com/femboy/yip</text>')
    lines.append('  </g>')

    lines.append('</svg>')
    return "\n".join(lines) + "\n"


def main():
    repo_root = Path(__file__).resolve().parent.parent.parent
    assets_dir = repo_root / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)

    svg_path = assets_dir / "architecture.svg"
    svg_content = build_architecture_svg()

    # Validate XML before writing
    ET.fromstring(svg_content)

    svg_path.write_text(svg_content, encoding="utf-8")
    print(f"Generated: {svg_path} ({len(svg_content)} bytes)")


if __name__ == "__main__":
    main()
