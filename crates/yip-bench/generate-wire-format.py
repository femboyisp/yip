#!/usr/bin/env python3
"""
generate-wire-format.py

Deterministic vector SVG diagram generator for yip wire protocol & cryptographic ceremony.
Generates:
  assets/wire-format.svg

Visualizes four key architectural pillars of yip:
  1. Panel A: Data-Plane Datagram Framing (Anti-DPI Keyed Header Protection & SipHash-1-3 MAC)
  2. Panel B: Post-Quantum Hybrid Handshake Framing (Noise-IKpsk2 + ML-KEM-512 Kyber)
  3. Panel C: 120-Second Epoch Ratchet Overlap (Zero-Loss Rekey Rotation)
  4. Panel D: Cryptographic Self-Certifying Node Addressing (fd00::/8 ULA via BLAKE2s)

Standard library only. Strict determinism (fixed formatting, fixed float precision, no timestamps).
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
COLOR_TEXT_MAIN = "#f0f6fc"
COLOR_TEXT_MUTED = "#8b949e"
COLOR_TEXT_DIM = "#6e7681"

# Domain Colors
# Obfuscation & Header Protection
COLOR_OBF = "#f97316"           # Fox Orange
COLOR_OBF_LIGHT = "#fb923c"     # Amber
COLOR_OBF_BG = "#431407"        # Dark Amber / Brown

# Classical Identity & Noise IK
COLOR_NOISE = "#38bdf8"         # Sky Blue
COLOR_NOISE_LIGHT = "#818cf8"   # Indigo / Light Sky
COLOR_NOISE_BG = "#1e1b4b"      # Deep Indigo

# Post-Quantum ML-KEM-512
COLOR_PQ = "#10b981"            # Emerald Green
COLOR_PQ_LIGHT = "#34d399"      # Mint Green
COLOR_PQ_BG = "#064e3b"         # Deep Emerald

# Epoch Ratchet & Overlap
COLOR_EPOCH = "#a855f7"         # Purple
COLOR_EPOCH_LIGHT = "#c084fc"   # Light Purple
COLOR_EPOCH_BG = "#3b0764"      # Deep Purple

COLOR_DATA = "#06b6d4"          # Cyan
COLOR_DATA_LIGHT = "#22d3ee"
COLOR_DATA_BG = "#083344"

COLOR_RED = "#ef4444"
COLOR_GREEN = "#22c55e"


def escape_xml(s: str) -> str:
    """Escape XML special characters deterministically."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


class SvgCanvas:
    """Deterministic XML builder for vector SVG diagrams."""

    def __init__(self, width: int = 1040, height: int = 820):
        self.width = width
        self.height = height
        self.defs = []
        self.elements = []

    def add_def(self, def_str: str):
        self.defs.append(def_str)

    def rect(self, x: float, y: float, w: float, h: float, rx: float = 0.0,
             fill: str = "none", stroke: str = "none", stroke_width: float = 1.0,
             opacity: float = 1.0, stroke_dasharray: str = ""):
        attrs = [
            f'x="{x:.2f}"', f'y="{y:.2f}"',
            f'width="{w:.2f}"', f'height="{h:.2f}"',
            f'fill="{fill}"'
        ]
        if rx > 0:
            attrs.append(f'rx="{rx:.2f}"')
        if stroke != "none":
            attrs.extend([f'stroke="{stroke}"', f'stroke-width="{stroke_width:.2f}"'])
        if opacity < 1.0:
            attrs.append(f'opacity="{opacity:.2f}"')
        if stroke_dasharray:
            attrs.append(f'stroke-dasharray="{stroke_dasharray}"')
        self.elements.append(f'<rect {" ".join(attrs)} />')

    def line(self, x1: float, y1: float, x2: float, y2: float,
             stroke: str, stroke_width: float = 1.0, stroke_dasharray: str = "",
             marker_end: str = ""):
        attrs = [
            f'x1="{x1:.2f}"', f'y1="{y1:.2f}"',
            f'x2="{x2:.2f}"', f'y2="{y2:.2f}"',
            f'stroke="{stroke}"', f'stroke-width="{stroke_width:.2f}"'
        ]
        if stroke_dasharray:
            attrs.append(f'stroke-dasharray="{stroke_dasharray}"')
        if marker_end:
            attrs.append(f'marker-end="{marker_end}"')
        self.elements.append(f'<line {" ".join(attrs)} />')

    def text(self, x: float, y: float, content: str, fill: str = COLOR_TEXT_MAIN,
             font_size: float = 12.0, font_family: str = FONT_SANS,
             font_weight: str = "normal", text_anchor: str = "start"):
        attrs = [
            f'x="{x:.2f}"', f'y="{y:.2f}"',
            f'fill="{fill}"',
            f'font-size="{font_size:.1f}"',
            f'font-family="{font_family}"',
            f'font-weight="{font_weight}"',
            f'text-anchor="{text_anchor}"'
        ]
        escaped = escape_xml(content)
        self.elements.append(f'<text {" ".join(attrs)}>{escaped}</text>')

    def polygon(self, points: str, fill: str = "none", stroke: str = "none",
                stroke_width: float = 1.0):
        attrs = [f'points="{points}"', f'fill="{fill}"']
        if stroke != "none":
            attrs.extend([f'stroke="{stroke}"', f'stroke-width="{stroke_width:.2f}"'])
        self.elements.append(f'<polygon {" ".join(attrs)} />')

    def path(self, d: str, fill: str = "none", stroke: str = "none",
             stroke_width: float = 1.0):
        attrs = [f'd="{d}"', f'fill="{fill}"']
        if stroke != "none":
            attrs.extend([f'stroke="{stroke}"', f'stroke-width="{stroke_width:.2f}"'])
        self.elements.append(f'<path {" ".join(attrs)} />')

    def render(self) -> str:
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.width} {self.height}" width="{self.width}" height="{self.height}">'
        ]
        if self.defs:
            lines.append('  <defs>')
            for d in self.defs:
                lines.append(f'    {d}')
            lines.append('  </defs>')
        for el in self.elements:
            lines.append(f'  {el}')
        lines.append('</svg>')
        return "\n".join(lines) + "\n"


def generate_wire_format_svg() -> str:
    w = 1040
    h = 820
    canvas = SvgCanvas(width=w, height=h)

    # Markers & Definitions
    marker_colors = {
        "dim": COLOR_TEXT_DIM,
        "noise": COLOR_NOISE,
        "data": COLOR_DATA,
        "obf": COLOR_OBF,
        "pq": COLOR_PQ,
        "epoch": COLOR_EPOCH,
    }
    for name, col in marker_colors.items():
        canvas.add_def(
            f'<marker id="arrow-{name}" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">'
            f'<path d="M0,0 L0,6 L6,3 z" fill="{col}" /></marker>'
        )

    # Subtle Gradients
    canvas.add_def(
        f'<linearGradient id="grad-card-bg" x1="0%" y1="0%" x2="0%" y2="100%">'
        f'<stop offset="0%" stop-color="{COLOR_CARD_BG}" stop-opacity="0.95" />'
        f'<stop offset="100%" stop-color="{COLOR_SUB_CARD_BG}" stop-opacity="0.98" />'
        f'</linearGradient>'
    )
    canvas.add_def(
        f'<linearGradient id="grad-panel-a" x1="0%" y1="0%" x2="0%" y2="100%">'
        f'<stop offset="0%" stop-color="{COLOR_OBF}" stop-opacity="0.08" />'
        f'<stop offset="100%" stop-color="{COLOR_CARD_BG}" stop-opacity="0.95" />'
        f'</linearGradient>'
    )
    canvas.add_def(
        f'<linearGradient id="grad-panel-b" x1="0%" y1="0%" x2="0%" y2="100%">'
        f'<stop offset="0%" stop-color="{COLOR_PQ}" stop-opacity="0.08" />'
        f'<stop offset="100%" stop-color="{COLOR_CARD_BG}" stop-opacity="0.95" />'
        f'</linearGradient>'
    )
    canvas.add_def(
        f'<linearGradient id="grad-panel-c" x1="0%" y1="0%" x2="0%" y2="100%">'
        f'<stop offset="0%" stop-color="{COLOR_EPOCH}" stop-opacity="0.08" />'
        f'<stop offset="100%" stop-color="{COLOR_CARD_BG}" stop-opacity="0.95" />'
        f'</linearGradient>'
    )
    canvas.add_def(
        f'<linearGradient id="grad-panel-d" x1="0%" y1="0%" x2="0%" y2="100%">'
        f'<stop offset="0%" stop-color="{COLOR_NOISE}" stop-opacity="0.08" />'
        f'<stop offset="100%" stop-color="{COLOR_CARD_BG}" stop-opacity="0.95" />'
        f'</linearGradient>'
    )

    # Background Canvas
    canvas.rect(0.75, 0.75, w - 1.5, h - 1.5, rx=12.0, fill=COLOR_CANVAS_BG, stroke=COLOR_CANVAS_BORDER, stroke_width=1.5)

    # =========================================================================
    # TOP HEADER SECTION
    # =========================================================================
    # Fox Badge
    canvas.rect(24.0, 20.0, 76.0, 24.0, rx=6.0, fill=COLOR_OBF_BG, stroke=COLOR_OBF, stroke_width=1.0)
    canvas.polygon("34.00,36.00 39.00,26.00 44.00,31.00 49.00,26.00 54.00,36.00 44.00,39.00", fill=COLOR_OBF_LIGHT)
    canvas.text(73.0, 36.0, "YIP", fill=COLOR_OBF_LIGHT, font_size=11.0, font_family=FONT_MONO, font_weight="700", text_anchor="middle")

    # Main Title & Subtitle
    canvas.text(112.0, 35.0, "yip Wire Protocol & Cryptographic Ceremony", fill=COLOR_TEXT_MAIN, font_size=18.0, font_weight="700")
    canvas.text(
        112.0, 52.0,
        "Zero-Fixed-Signature Keyed Header Protection • Noise-IKpsk2 + ML-KEM-512 PQ Hybrid • 120s Ratchet Overlap • Self-Certifying IPv6",
        fill=COLOR_TEXT_MUTED, font_size=11.0
    )

    # =========================================================================
    # PANEL GEOMETRY SETUP (2x2 Grid)
    # =========================================================================
    # 2 columns x 2 rows
    # Col 1: x = 24.0, w = 486.0
    # Col 2: x = 530.0, w = 486.0
    # Row 1: y = 68.0, h = 344.0
    # Row 2: y = 424.0, h = 344.0
    # Footer line at y = 780.0
    p1_x, p1_y, p1_w, p1_h = 24.0, 68.0, 486.0, 344.0
    p2_x, p2_y, p2_w, p2_h = 530.0, 68.0, 486.0, 344.0
    p3_x, p3_y, p3_w, p3_h = 24.0, 424.0, 486.0, 344.0
    p4_x, p4_y, p4_w, p4_h = 530.0, 424.0, 486.0, 344.0

    # =========================================================================
    # PANEL A: DATA-PLANE DATAGRAM FRAMING (ANTI-DPI & HEADER PROTECTION)
    # =========================================================================
    canvas.rect(p1_x, p1_y, p1_w, p1_h, rx=8.0, fill="url(#grad-panel-a)", stroke=COLOR_CANVAS_BORDER, stroke_width=1.0)

    # Header badge & title
    canvas.rect(40.0, 84.0, 82.0, 20.0, rx=4.0, fill=COLOR_OBF_BG, stroke=COLOR_OBF, stroke_width=1.0)
    canvas.text(81.0, 98.0, "PANEL A", fill=COLOR_OBF_LIGHT, font_size=9.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(132.0, 98.0, "Data-Plane Datagram Framing", fill=COLOR_TEXT_MAIN, font_size=13.0, font_weight="700")
    canvas.text(40.0, 118.0, "Anti-DPI Keyed Header Protection (XOR Keystream & SipHash MAC)", fill=COLOR_TEXT_MUTED, font_size=10.5)

    # Byte-by-byte visual breakdown strip
    # Usable width: 454px (from 40 to 494)
    # Block 1: Bytes 0..15 (w = 140)
    # Block 2: Bytes 15..(N-8) (w = 206)
    # Block 3: Bytes (N-8)..N (w = 100)
    # Spacing: 40, 184, 394
    canvas.rect(40.0, 130.0, 140.0, 46.0, rx=4.0, fill="#271406", stroke=COLOR_OBF, stroke_width=1.0)
    canvas.text(110.0, 144.0, "Bytes 0..15 (15B)", fill=COLOR_OBF_LIGHT, font_size=9.0, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(110.0, 158.0, "Masked Wire Header", fill=COLOR_TEXT_MAIN, font_size=10.5, font_weight="700", text_anchor="middle")
    canvas.text(110.0, 170.0, "SipHash-1-3 CTR Mask", fill=COLOR_TEXT_MUTED, font_size=8.5, text_anchor="middle")

    canvas.rect(184.0, 130.0, 206.0, 46.0, rx=4.0, fill=COLOR_DATA_BG, stroke=COLOR_DATA, stroke_width=1.0)
    canvas.text(287.0, 144.0, "Bytes 15..(N-8) (Variable MTU)", fill=COLOR_DATA_LIGHT, font_size=9.0, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(287.0, 158.0, "Encrypted Symbol Payload", fill=COLOR_TEXT_MAIN, font_size=10.5, font_weight="700", text_anchor="middle")
    canvas.text(287.0, 170.0, "Counter(8B) ‖ Size(4B) ‖ Ciphertext + Poly1305", fill=COLOR_TEXT_MUTED, font_size=8.0, text_anchor="middle")

    canvas.rect(394.0, 130.0, 100.0, 46.0, rx=4.0, fill="#1c1917", stroke=COLOR_OBF, stroke_width=1.0)
    canvas.text(444.0, 144.0, "Bytes (N-8)..N (8B)", fill=COLOR_OBF_LIGHT, font_size=9.0, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(444.0, 158.0, "Trailing Auth Tag", fill=COLOR_TEXT_MAIN, font_size=10.5, font_weight="700", text_anchor="middle")
    canvas.text(444.0, 170.0, "SipHash-1-3 Coverage MAC", fill=COLOR_TEXT_MUTED, font_size=8.0, text_anchor="middle")

    # Bitfield breakdown sub-card
    canvas.text(40.0, 195.0, "Unmasked Logical Header Layout (15 Bytes / 120 bits):", fill=COLOR_TEXT_MUTED, font_size=9.5, font_family=FONT_MONO)
    bf_y = 204.0
    # Fields: conn_tag (u64 / 8B): 176px, object_id (u16 / 2B): 86px, payload_id ([u8; 4] / 4B): 114px, flags (u8 / 1B): 66px
    canvas.rect(40.0, bf_y, 176.0, 36.0, rx=3.0, fill=COLOR_NOISE_BG, stroke=COLOR_NOISE_LIGHT, stroke_width=1.0)
    canvas.text(128.0, bf_y + 14.0, "conn_tag (8B / 64b)", fill=COLOR_NOISE_LIGHT, font_size=9.0, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(128.0, bf_y + 28.0, "Rotating Session Token", fill=COLOR_TEXT_MUTED, font_size=8.0, text_anchor="middle")

    canvas.rect(220.0, bf_y, 86.0, 36.0, rx=3.0, fill=COLOR_EPOCH_BG, stroke=COLOR_EPOCH_LIGHT, stroke_width=1.0)
    canvas.text(263.0, bf_y + 14.0, "object_id (2B / 16b)", fill=COLOR_EPOCH_LIGHT, font_size=9.0, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(263.0, bf_y + 28.0, "FEC Object ID", fill=COLOR_TEXT_MUTED, font_size=8.0, text_anchor="middle")

    canvas.rect(310.0, bf_y, 114.0, 36.0, rx=3.0, fill=COLOR_DATA_BG, stroke=COLOR_DATA_LIGHT, stroke_width=1.0)
    canvas.text(367.0, bf_y + 14.0, "payload_id (4B / 32b)", fill=COLOR_DATA_LIGHT, font_size=9.0, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(367.0, bf_y + 28.0, "RS Tag + Symbol Idx", fill=COLOR_TEXT_MUTED, font_size=8.0, text_anchor="middle")

    canvas.rect(428.0, bf_y, 66.0, 36.0, rx=3.0, fill=COLOR_CARD_BG, stroke=COLOR_TEXT_DIM, stroke_width=1.0)
    canvas.text(461.0, bf_y + 14.0, "flags (1B / 8b)", fill=COLOR_TEXT_MUTED, font_size=9.0, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(461.0, bf_y + 28.0, "Flow Class", fill=COLOR_TEXT_DIM, font_size=8.0, text_anchor="middle")

    canvas.text(40.0, 251.0, "⊕ Zero heap-alloc SipHash-1-3 CTR mask; datagrams appear random to DPI.", fill=COLOR_OBF_LIGHT, font_size=8.8, font_family=FONT_MONO)

    # Explanatory callout box
    cb_y = 265.0
    canvas.rect(40.0, cb_y, 454.0, 72.0, rx=6.0, fill="#1c1917", stroke=COLOR_OBF, stroke_width=1.0)
    # Shield icon path
    canvas.path(f"M 54.00,{cb_y + 18.0:.2f} L 60.00,{cb_y + 15.0:.2f} L 66.00,{cb_y + 18.0:.2f} L 66.00,{cb_y + 25.0:.2f} C 66.00,{cb_y + 32.0:.2f} 60.00,{cb_y + 36.0:.2f} 60.00,{cb_y + 36.0:.2f} C 60.00,{cb_y + 36.0:.2f} 54.00,{cb_y + 32.0:.2f} 54.00,{cb_y + 25.0:.2f} Z", fill=COLOR_OBF_LIGHT)
    canvas.text(74.0, cb_y + 20.0, "Anti-DPI Guarantee: Zero Static Signatures", fill=COLOR_TEXT_MAIN, font_size=10.5, font_weight="700")
    canvas.text(74.0, cb_y + 35.0, "15B header protected by SipHash-1-3 CTR keystream seeded by 8B trailing auth tag.", fill=COLOR_TEXT_MUTED, font_size=9.0)
    canvas.text(74.0, cb_y + 48.0, "Eliminates magic bytes, packet types, and static discriminators across the entire wire.", fill=COLOR_TEXT_MUTED, font_size=9.0)
    canvas.text(74.0, cb_y + 62.0, "Constant-time SipHash MAC tag check rejects forged headers in <12ns prior to decode.", fill=COLOR_TEXT_DIM, font_size=8.5)

    # Outcome banner
    ob_y = 344.0
    canvas.rect(40.0, ob_y, 454.0, 24.0, rx=4.0, fill=COLOR_SUB_CARD_BG, stroke=COLOR_CANVAS_BORDER, stroke_width=1.0)
    canvas.text(267.0, ob_y + 16.0, "DPI Resistance: Pass (0 signatures detected across 4-Engine Oracle)", fill=COLOR_PQ_LIGHT, font_size=9.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")

    # =========================================================================
    # PANEL B: POST-QUANTUM HYBRID HANDSHAKE (NOISE-IKPSK2 + ML-KEM-512)
    # =========================================================================
    canvas.rect(p2_x, p2_y, p2_w, p2_h, rx=8.0, fill="url(#grad-panel-b)", stroke=COLOR_CANVAS_BORDER, stroke_width=1.0)

    # Header badge & title
    canvas.rect(546.0, 84.0, 82.0, 20.0, rx=4.0, fill=COLOR_PQ_BG, stroke=COLOR_PQ, stroke_width=1.0)
    canvas.text(587.0, 98.0, "PANEL B", fill=COLOR_PQ_LIGHT, font_size=9.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(638.0, 98.0, "Post-Quantum Hybrid Handshake", fill=COLOR_TEXT_MAIN, font_size=13.0, font_weight="700")
    canvas.text(546.0, 118.0, "Noise-IKpsk2 + ML-KEM-512 (Kyber) • Sub-1200B Single-RTT", fill=COLOR_TEXT_MUTED, font_size=10.5)

    # Message 1 Breakdown (1,028 Bytes)
    canvas.text(546.0, 137.0, "Message 1 (Initiator → Responder) — 1,028 Bytes:", fill=COLOR_PQ_LIGHT, font_size=9.5, font_family=FONT_MONO, font_weight="700")
    m1_y = 144.0
    # Segments: Hdr(4B): 44px, ek_A(800B): 182px, e_A(32B): 76px, Enc(s_A||Cert_A)+Tag(144B): 146px (sum=448+6=454)
    canvas.rect(546.0, m1_y, 44.0, 34.0, rx=3.0, fill=COLOR_CARD_BG, stroke=COLOR_OBF, stroke_width=1.0)
    canvas.text(568.0, m1_y + 14.0, "Hdr", fill=COLOR_OBF_LIGHT, font_size=8.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(568.0, m1_y + 26.0, "4B", fill=COLOR_TEXT_MUTED, font_size=8.0, text_anchor="middle")

    canvas.rect(592.0, m1_y, 182.0, 34.0, rx=3.0, fill=COLOR_PQ_BG, stroke=COLOR_PQ, stroke_width=1.0)
    canvas.text(683.0, m1_y + 14.0, "ek_A (800B ML-KEM-512 pk)", fill=COLOR_PQ_LIGHT, font_size=9.0, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(683.0, m1_y + 26.0, "Post-Quantum Encapsulation Key", fill=COLOR_TEXT_MUTED, font_size=8.0, text_anchor="middle")

    canvas.rect(776.0, m1_y, 76.0, 34.0, rx=3.0, fill=COLOR_NOISE_BG, stroke=COLOR_NOISE_LIGHT, stroke_width=1.0)
    canvas.text(814.0, m1_y + 14.0, "e_A (32B)", fill=COLOR_NOISE_LIGHT, font_size=8.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(814.0, m1_y + 26.0, "Noise Ephem", fill=COLOR_TEXT_MUTED, font_size=8.0, text_anchor="middle")

    canvas.rect(854.0, m1_y, 146.0, 34.0, rx=3.0, fill=COLOR_DATA_BG, stroke=COLOR_DATA, stroke_width=1.0)
    canvas.text(927.0, m1_y + 14.0, "Enc(s_A ‖ Cert_A) + Tag", fill=COLOR_DATA_LIGHT, font_size=8.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(927.0, m1_y + 26.0, "Static Key + CA Cert (144B)", fill=COLOR_TEXT_MUTED, font_size=8.0, text_anchor="middle")

    # Message 2 Breakdown (948 Bytes)
    canvas.text(546.0, 193.0, "Message 2 (Responder → Initiator) — 948 Bytes:", fill=COLOR_PQ_LIGHT, font_size=9.5, font_family=FONT_MONO, font_weight="700")
    m2_y = 200.0
    # Segments: Hdr(4B): 44px, ct(768B): 182px, e_B(32B): 76px, Enc(Cert_B)+Tag(144B): 146px (sum=454)
    canvas.rect(546.0, m2_y, 44.0, 34.0, rx=3.0, fill=COLOR_CARD_BG, stroke=COLOR_OBF, stroke_width=1.0)
    canvas.text(568.0, m2_y + 14.0, "Hdr", fill=COLOR_OBF_LIGHT, font_size=8.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(568.0, m2_y + 26.0, "4B", fill=COLOR_TEXT_MUTED, font_size=8.0, text_anchor="middle")

    canvas.rect(592.0, m2_y, 182.0, 34.0, rx=3.0, fill=COLOR_PQ_BG, stroke=COLOR_PQ, stroke_width=1.0)
    canvas.text(683.0, m2_y + 14.0, "ct (768B ML-KEM-512 ct)", fill=COLOR_PQ_LIGHT, font_size=9.0, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(683.0, m2_y + 26.0, "Post-Quantum Ciphertext Envelope", fill=COLOR_TEXT_MUTED, font_size=8.0, text_anchor="middle")

    canvas.rect(776.0, m2_y, 76.0, 34.0, rx=3.0, fill=COLOR_NOISE_BG, stroke=COLOR_NOISE_LIGHT, stroke_width=1.0)
    canvas.text(814.0, m2_y + 14.0, "e_B (32B)", fill=COLOR_NOISE_LIGHT, font_size=8.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(814.0, m2_y + 26.0, "Noise Ephem", fill=COLOR_TEXT_MUTED, font_size=8.0, text_anchor="middle")

    canvas.rect(854.0, m2_y, 146.0, 34.0, rx=3.0, fill=COLOR_DATA_BG, stroke=COLOR_DATA, stroke_width=1.0)
    canvas.text(927.0, m2_y + 14.0, "Enc(Cert_B) + Tag", fill=COLOR_DATA_LIGHT, font_size=8.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(927.0, m2_y + 26.0, "Responder CA Cert (144B)", fill=COLOR_TEXT_MUTED, font_size=8.0, text_anchor="middle")

    # Technical Details Sub-card
    info_y = 246.0
    canvas.rect(546.0, info_y, 454.0, 90.0, rx=6.0, fill=COLOR_SUB_CARD_BG, stroke=COLOR_CANVAS_BORDER, stroke_width=1.0)
    canvas.text(558.0, info_y + 17.0, "✓ Sub-1,200B MTU: Msg 1 (1,028B) & Msg 2 (948B) < 1,200B OBF_MTU_BUDGET", fill=COLOR_PQ_LIGHT, font_size=9.0, font_family=FONT_MONO, font_weight="700")
    canvas.text(558.0, info_y + 33.0, "• Deadlock-Free: Initiator parses cleartext ct at [4..772], computes", fill=COLOR_TEXT_MUTED, font_size=9.0)
    canvas.text(558.0, info_y + 46.0, "  Decaps(dk_A, ct) -> ss, and calls set_psk(2, &ss) before decrypting.", fill=COLOR_TEXT_MUTED, font_size=9.0)
    canvas.text(558.0, info_y + 61.0, "• FIPS 203 §7.2: Modulus (< 3329) validated; IND-CCA2 rejection on tamper.", fill=COLOR_PQ_LIGHT, font_size=9.0, font_weight="700")
    canvas.text(558.0, info_y + 75.0, "• Ephemeral Zeroize: Decapsulation keys and intermediate secrets scrubbed on Drop.", fill=COLOR_TEXT_DIM, font_size=8.5)

    # Outcome banner
    ob2_y = 344.0
    canvas.rect(546.0, ob2_y, 454.0, 24.0, rx=4.0, fill=COLOR_PQ_BG, stroke=COLOR_PQ, stroke_width=1.0)
    canvas.text(773.0, ob2_y + 16.0, "PQ Security: Quantum-Safe (FIPS 203 Cat 1 ML-KEM-512 + X25519 Hybrid)", fill=COLOR_PQ_LIGHT, font_size=9.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")

    # =========================================================================
    # PANEL C: 120-SECOND EPOCH KEY RATCHET OVERLAP (ZERO-LOSS ROTATION)
    # =========================================================================
    canvas.rect(p3_x, p3_y, p3_w, p3_h, rx=8.0, fill="url(#grad-panel-c)", stroke=COLOR_CANVAS_BORDER, stroke_width=1.0)

    # Header badge & title
    canvas.rect(40.0, 440.0, 82.0, 20.0, rx=4.0, fill=COLOR_EPOCH_BG, stroke=COLOR_EPOCH, stroke_width=1.0)
    canvas.text(81.0, 454.0, "PANEL C", fill=COLOR_EPOCH_LIGHT, font_size=9.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(132.0, 454.0, "120s Epoch Ratchet Overlap", fill=COLOR_TEXT_MAIN, font_size=13.0, font_weight="700")
    canvas.text(40.0, 474.0, "Continuous Forward Secrecy • Zero-Drop Rekey Transition", fill=COLOR_TEXT_MUTED, font_size=10.5)

    # Timeline diagram
    # Usable width: 454. Axis: x from 60 to 470 (w = 410).
    # Overlap Window Shading (260s to 440s: x = 260 to 440, w = 180)
    canvas.rect(260.0, 492.0, 180.0, 68.0, rx=4.0, fill=COLOR_EPOCH, stroke=COLOR_EPOCH_LIGHT, stroke_width=1.0, opacity=0.15, stroke_dasharray="3,3")
    canvas.text(350.0, 488.0, "20s Overlap Window (110s..130s)", fill=COLOR_EPOCH_LIGHT, font_size=8.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")

    # Epoch N Bar (y = 500, h = 24)
    # Active: x=60 to 260 (w=200). Grace RX: x=260 to 440 (w=180)
    canvas.rect(60.0, 500.0, 200.0, 24.0, rx=4.0, fill=COLOR_EPOCH_BG, stroke=COLOR_EPOCH, stroke_width=1.2)
    canvas.text(160.0, 516.0, "Epoch N Active (TX + RX)", fill=COLOR_TEXT_MAIN, font_size=9.5, font_weight="700", text_anchor="middle")

    canvas.rect(260.0, 500.0, 180.0, 24.0, rx=4.0, fill="#2e1065", stroke=COLOR_EPOCH_LIGHT, stroke_width=1.0, stroke_dasharray="2,2")
    canvas.text(350.0, 516.0, "RX Only Grace Window", fill=COLOR_EPOCH_LIGHT, font_size=9.0, font_family=FONT_MONO, font_weight="700", text_anchor="middle")

    # Epoch N+1 Bar (y = 532, h = 24)
    # Rekey handshake: x=260 to 290 (w=30). Active: x=295 to 470 (w=175)
    canvas.rect(260.0, 532.0, 32.0, 24.0, rx=3.0, fill=COLOR_OBF_BG, stroke=COLOR_OBF, stroke_width=1.0)
    canvas.text(276.0, 547.0, "HS", fill=COLOR_OBF_LIGHT, font_size=8.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")

    canvas.rect(296.0, 532.0, 174.0, 24.0, rx=4.0, fill=COLOR_PQ_BG, stroke=COLOR_PQ, stroke_width=1.2)
    canvas.text(383.0, 547.0, "Epoch N+1 Active (TX + RX)", fill=COLOR_PQ_LIGHT, font_size=9.0, font_weight="700", text_anchor="middle")

    # Timeline axis line & ticks at y = 563.0
    canvas.line(60.0, 563.0, 470.0, 563.0, stroke=COLOR_CANVAS_BORDER, stroke_width=1.0)
    # Ticks with non-colliding labels (time on top line, event on bottom line)
    ticks = [
        (60.0, "t = 0s", None, COLOR_TEXT_MUTED),
        (160.0, "t = 60s", None, COLOR_TEXT_DIM),
        (260.0, "t = 110s", "Rekey HS", COLOR_OBF_LIGHT),
        (350.0, "t = 120s", "Epoch End", COLOR_TEXT_MUTED),
        (440.0, "t = 130s", "Zeroize", COLOR_RED),
    ]
    for tx, tlabel, sublabel, tcol in ticks:
        canvas.line(tx, 560.0, tx, 566.0, stroke=COLOR_TEXT_DIM, stroke_width=1.0)
        canvas.text(tx, 575.0, tlabel, fill=tcol, font_size=8.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
        if sublabel:
            canvas.text(tx, 585.0, sublabel, fill=tcol, font_size=7.5, font_family=FONT_MONO, text_anchor="middle")

    # Explanatory subcard
    ratchet_info_y = 596.0
    canvas.rect(40.0, ratchet_info_y, 454.0, 102.0, rx=6.0, fill=COLOR_SUB_CARD_BG, stroke=COLOR_CANVAS_BORDER, stroke_width=1.0)
    canvas.text(54.0, ratchet_info_y + 18.0, "• Seamless Egress Switch: Outbound frames jump to Epoch N+1 immediately.", fill=COLOR_TEXT_MUTED, font_size=9.0)
    canvas.text(54.0, ratchet_info_y + 35.0, "• Dual-Receive Window (110s..130s): Accepts packets encrypted under both", fill=COLOR_TEXT_MUTED, font_size=9.0)
    canvas.text(54.0, ratchet_info_y + 49.0, "  Epoch N and Epoch N+1 without drops or decryption errors.", fill=COLOR_TEXT_MUTED, font_size=9.0)
    canvas.text(54.0, ratchet_info_y + 68.0, "• Zeroize on Retire: At t = 130s, Epoch N secrets scrubbed from RAM.", fill=COLOR_EPOCH_LIGHT, font_size=9.0, font_weight="700")
    canvas.text(54.0, ratchet_info_y + 86.0, "• 0% Packet Loss: Eliminates rekey stalls and head-of-line blocking.", fill=COLOR_PQ_LIGHT, font_size=9.0, font_weight="700")

    # Outcome banner
    ob3_y = 704.0
    canvas.rect(40.0, ob3_y, 454.0, 24.0, rx=4.0, fill="#2e1065", stroke=COLOR_EPOCH, stroke_width=1.0)
    canvas.text(267.0, ob3_y + 16.0, "Rotation Guarantee: 0% Dropped Packets During Continuous Key Refresh", fill=COLOR_EPOCH_LIGHT, font_size=9.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")

    # =========================================================================
    # PANEL D: CRYPTOGRAPHIC NODE ADDRESSING (FD00::/8)
    # =========================================================================
    canvas.rect(p4_x, p4_y, p4_w, p4_h, rx=8.0, fill="url(#grad-panel-d)", stroke=COLOR_CANVAS_BORDER, stroke_width=1.0)

    # Header badge & title
    canvas.rect(546.0, 440.0, 82.0, 20.0, rx=4.0, fill=COLOR_NOISE_BG, stroke=COLOR_NOISE, stroke_width=1.0)
    canvas.text(587.0, 454.0, "PANEL D", fill=COLOR_NOISE, font_size=9.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(638.0, 454.0, "Cryptographic Node Addressing", fill=COLOR_TEXT_MAIN, font_size=13.0, font_weight="700")
    canvas.text(546.0, 474.0, "Self-Certifying IPv6 ULA (fd00::/8) • Zero Central Authority", fill=COLOR_TEXT_MUTED, font_size=10.5)

    # Flow pipeline: Step 1 (Keypair) -> Step 2 (BLAKE2s) -> Step 3 (IPv6 Address)
    flow_y = 492.0
    # Box 1: Node Keypair
    canvas.rect(546.0, flow_y, 126.0, 44.0, rx=4.0, fill=COLOR_NOISE_BG, stroke=COLOR_NOISE_LIGHT, stroke_width=1.0)
    canvas.text(609.0, flow_y + 16.0, "Ed25519 Identity", fill=COLOR_NOISE_LIGHT, font_size=9.5, font_weight="700", text_anchor="middle")
    canvas.text(609.0, flow_y + 30.0, "32-byte Public Key", fill=COLOR_TEXT_MUTED, font_size=8.5, font_family=FONT_MONO, text_anchor="middle")

    # Arrow 1
    canvas.line(674.0, flow_y + 22.0, 692.0, flow_y + 22.0, stroke=COLOR_TEXT_DIM, stroke_width=1.2, marker_end="url(#arrow-dim)")

    # Box 2: BLAKE2s Hash
    canvas.rect(696.0, flow_y, 148.0, 44.0, rx=4.0, fill=COLOR_DATA_BG, stroke=COLOR_DATA_LIGHT, stroke_width=1.0)
    canvas.text(770.0, flow_y + 16.0, "BLAKE2s-128", fill=COLOR_DATA_LIGHT, font_size=9.5, font_weight="700", text_anchor="middle")
    canvas.text(770.0, flow_y + 30.0, '"yip-node-v1" ‖ pubkey', fill=COLOR_TEXT_MUTED, font_size=8.5, font_family=FONT_MONO, text_anchor="middle")

    # Arrow 2
    canvas.line(846.0, flow_y + 22.0, 864.0, flow_y + 22.0, stroke=COLOR_TEXT_DIM, stroke_width=1.2, marker_end="url(#arrow-dim)")

    # Box 3: Self-Certifying IPv6
    canvas.rect(868.0, flow_y, 132.0, 44.0, rx=4.0, fill=COLOR_PQ_BG, stroke=COLOR_PQ_LIGHT, stroke_width=1.0)
    canvas.text(934.0, flow_y + 16.0, "IPv6 Node Address", fill=COLOR_PQ_LIGHT, font_size=9.5, font_weight="700", text_anchor="middle")
    canvas.text(934.0, flow_y + 30.0, "fd00::/8 ULA Space", fill=COLOR_TEXT_MUTED, font_size=8.5, font_family=FONT_MONO, text_anchor="middle")

    # Address Bitfield Breakdown (128 bits / 16 Bytes)
    canvas.text(546.0, 551.0, "Self-Certifying IPv6 Bitfield Breakdown (128 bits / 16 Bytes):", fill=COLOR_TEXT_MUTED, font_size=9.5, font_family=FONT_MONO)
    addr_y = 558.0
    # Bitfield cells: Prefix(8b): 74px, Digest[0..7](56b): 186px, Digest[7..15](64b): 190px (sum = 450 + 4 = 454)
    canvas.rect(546.0, addr_y, 74.0, 32.0, rx=3.0, fill=COLOR_OBF_BG, stroke=COLOR_OBF, stroke_width=1.0)
    canvas.text(583.0, addr_y + 13.0, "0xfd (8 bits)", fill=COLOR_OBF_LIGHT, font_size=8.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(583.0, addr_y + 25.0, "IPv6 ULA Prefix", fill=COLOR_TEXT_MUTED, font_size=7.5, text_anchor="middle")

    canvas.rect(622.0, addr_y, 186.0, 32.0, rx=3.0, fill=COLOR_NOISE_BG, stroke=COLOR_NOISE_LIGHT, stroke_width=1.0)
    canvas.text(715.0, addr_y + 13.0, "Digest[0..7] (56 bits)", fill=COLOR_NOISE_LIGHT, font_size=8.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(715.0, addr_y + 25.0, "Mesh Subnet / Routing ID", fill=COLOR_TEXT_MUTED, font_size=7.5, text_anchor="middle")

    canvas.rect(810.0, addr_y, 190.0, 32.0, rx=3.0, fill=COLOR_DATA_BG, stroke=COLOR_DATA_LIGHT, stroke_width=1.0)
    canvas.text(905.0, addr_y + 13.0, "Digest[7..15] (64 bits)", fill=COLOR_DATA_LIGHT, font_size=8.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")
    canvas.text(905.0, addr_y + 25.0, "Interface Identifier (Node ID)", fill=COLOR_TEXT_MUTED, font_size=7.5, text_anchor="middle")

    # Explanatory subcard
    addr_info_y = 598.0
    canvas.rect(546.0, addr_info_y, 454.0, 98.0, rx=6.0, fill=COLOR_SUB_CARD_BG, stroke=COLOR_CANVAS_BORDER, stroke_width=1.0)
    canvas.text(558.0, addr_info_y + 17.0, "• Self-Certifying: Address IS public key digest; IP spoofing impossible.", fill=COLOR_TEXT_MUTED, font_size=9.0)
    canvas.text(558.0, addr_info_y + 34.0, "• Zero Central Infrastructure: Autonomous routing without DHCP/IPAM/coordinators.", fill=COLOR_TEXT_MUTED, font_size=9.0)
    canvas.text(558.0, addr_info_y + 51.0, "• Collision Resistance: 120-bit BLAKE2s digest provides 2^60 collision floor.", fill=COLOR_TEXT_MUTED, font_size=9.0)
    canvas.text(558.0, addr_info_y + 68.0, "• Zero-Trust Admission: Node identity bound to CA Root Cert before admission.", fill=COLOR_NOISE, font_size=9.0, font_weight="700")
    canvas.text(558.0, addr_info_y + 85.0, "• Autonomous Routing: Nodes route directly to fd00::/8 ULA addresses across mesh.", fill=COLOR_TEXT_DIM, font_size=8.5)

    # Outcome banner
    ob4_y = 704.0
    canvas.rect(546.0, ob4_y, 454.0, 24.0, rx=4.0, fill=COLOR_NOISE_BG, stroke=COLOR_NOISE, stroke_width=1.0)
    canvas.text(773.0, ob4_y + 16.0, "Identity Invariant: Address = 0xfd ‖ BLAKE2s(pubkey)[0..15] (Zero Central IPAM)", fill=COLOR_NOISE, font_size=9.5, font_family=FONT_MONO, font_weight="700", text_anchor="middle")

    # =========================================================================
    # FOOTER SECTION
    # =========================================================================
    canvas.line(24.0, 780.0, w - 24.0, 780.0, stroke=COLOR_CANVAS_BORDER, stroke_width=1.0)
    canvas.text(
        28.0, 800.0,
        "Protocol: Noise-IKpsk2 • NIST FIPS 203 ML-KEM-512 • SipHash-CTR/2-4 • ChaCha20-Poly1305 • BLAKE2s",
        fill=COLOR_TEXT_DIM, font_size=9.0, font_family=FONT_MONO
    )
    canvas.text(
        w - 28.0, 800.0,
        "Deterministic Vector Wire Format • github.com/femboyisp/yip",
        fill=COLOR_TEXT_DIM, font_size=9.0, font_family=FONT_MONO, text_anchor="end"
    )

    return canvas.render()


def main():
    parser = argparse.ArgumentParser(description="Deterministic SVG wire format and ceremony diagram generator.")
    parser.add_argument("--output", type=Path, default=None,
                        help="Path to output SVG file (defaults to assets/wire-format.svg).")
    parser.add_argument("--check", action="store_true",
                        help="Check if SVG asset is up-to-date and valid XML without writing to disk.")
    parser.add_argument("--repo-root", type=Path, default=None,
                        help="Path to repository root (defaults to auto-detection).")
    args = parser.parse_args()

    if args.repo_root:
        repo_root = args.repo_root.resolve()
    else:
        repo_root = Path(__file__).resolve().parent.parent.parent

    target_path = args.output.resolve() if args.output else (repo_root / "assets" / "wire-format.svg")

    svg_content = generate_wire_format_svg()

    # Validate generated XML syntax
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
    print(f"Generated {target_path} ({len(svg_content)} bytes)")

    # Rasterize PNG
    png_path = target_path.with_suffix(".png")
    for cmd in ["magick", "convert"]:
        try:
            subprocess.run([cmd, "-density", "192", str(target_path), str(png_path)],
                           check=True, capture_output=True)
            if png_path.exists() and png_path.stat().st_size > 0:
                print(f"Rasterized: {png_path} ({png_path.stat().st_size / 1024:.1f} KB)")
                break
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue


if __name__ == "__main__":
    main()
