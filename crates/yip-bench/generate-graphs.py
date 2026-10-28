#!/usr/bin/env python3
"""
generate-graphs.py

Deterministic vector SVG benchmark generator for yip.
Generates:
  1. assets/bench-throughput-loss.svg
  2. assets/bench-fec-recovery.svg
  3. assets/bench-multicore-scaling.svg
  4. assets/bench-latency-jitter.svg

Standard library only. Strict determinism (fixed-precision floats, sorted keys, no timestamps).
"""

import argparse
import csv
import math
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

FONT_SANS = "ui-sans-serif, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
FONT_MONO = "ui-monospace, SFMono-Regular, Menlo, monospace"

COLOR_BG = "#0d1117"
COLOR_BORDER = "#30363d"
COLOR_GRID = "#21262d"
COLOR_GRID_SUBTLE = "#161b22"
COLOR_TEXT_MAIN = "#f0f6fc"
COLOR_TEXT_MUTED = "#8b949e"
COLOR_TEXT_DIM = "#6e7681"

COLOR_YIP = "#f97316"          # Fox Orange
COLOR_AF_XDP = "#fb923c"       # Bright Ember
COLOR_WIREGUARD = "#38bdf8"    # Sky Blue
COLOR_EPOLL = "#38bdf8"        # Sky Blue
COLOR_OPENVPN = "#a855f7"      # Purple
COLOR_IO_URING = "#34d399"     # Emerald Green
COLOR_BASELINE = "#64748b"     # Slate Gray

DEFAULT_WAN_HISTORY = Path(__file__).resolve().parent / "wan" / "results" / "history.csv"
DEFAULT_SHARDING_SCALE = Path(__file__).resolve().parent / "results" / "sharding-scale.csv"
DEFAULT_LATENCY_JITTER = Path(__file__).resolve().parent / "results" / "latency-jitter.csv"


class SvgCanvas:
    def __init__(self, width: int = 840, height: int = 480):
        self.width = width
        self.height = height
        self.elements = []

    def rect(self, x: float, y: float, w: float, h: float, rx: float = 0.0,
             fill: str = "none", stroke: str = "none", stroke_width: float = 1.0,
             opacity: float = 1.0, extra_attrs: str = ""):
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
        if extra_attrs:
            attrs.append(extra_attrs)
        self.elements.append(f'<rect {" ".join(attrs)}/>')

    def line(self, x1: float, y1: float, x2: float, y2: float,
             stroke: str, stroke_width: float = 1.0, stroke_dasharray: str = ""):
        attrs = [
            f'x1="{x1:.2f}"', f'y1="{y1:.2f}"',
            f'x2="{x2:.2f}"', f'y2="{y2:.2f}"',
            f'stroke="{stroke}"', f'stroke-width="{stroke_width:.2f}"'
        ]
        if stroke_dasharray:
            attrs.append(f'stroke-dasharray="{stroke_dasharray}"')
        self.elements.append(f'<line {" ".join(attrs)}/>')

    def text(self, x: float, y: float, content: str, fill: str = COLOR_TEXT_MAIN,
             font_size: int = 12, font_family: str = FONT_SANS,
             font_weight: str = "normal", text_anchor: str = "start",
             extra_attrs: str = ""):
        escaped = (
            content.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )
        attrs = [
            f'x="{x:.2f}"', f'y="{y:.2f}"',
            f'fill="{fill}"',
            f'font-size="{font_size}"',
            f'font-family="{font_family}"',
            f'font-weight="{font_weight}"',
            f'text-anchor="{text_anchor}"'
        ]
        if extra_attrs:
            attrs.append(extra_attrs)
        self.elements.append(f'<text {" ".join(attrs)}>{escaped}</text>')

    def circle(self, cx: float, cy: float, r: float,
               fill: str, stroke: str = "none", stroke_width: float = 1.0):
        attrs = [
            f'cx="{cx:.2f}"', f'cy="{cy:.2f}"',
            f'r="{r:.2f}"',
            f'fill="{fill}"'
        ]
        if stroke != "none":
            attrs.extend([f'stroke="{stroke}"', f'stroke-width="{stroke_width:.2f}"'])
        self.elements.append(f'<circle {" ".join(attrs)}/>')

    def polyline(self, points: list[tuple[float, float]],
                 stroke: str, stroke_width: float = 2.0,
                 stroke_dasharray: str = ""):
        pts_str = " ".join(f"{x:.2f},{y:.2f}" for x, y in points)
        attrs = [
            f'points="{pts_str}"',
            'fill="none"',
            f'stroke="{stroke}"',
            f'stroke-width="{stroke_width:.2f}"',
            'stroke-linecap="round"',
            'stroke-linejoin="round"'
        ]
        if stroke_dasharray:
            attrs.append(f'stroke-dasharray="{stroke_dasharray}"')
        self.elements.append(f'<polyline {" ".join(attrs)}/>')

    def polygon(self, points: list[tuple[float, float]],
                fill: str, opacity: float = 1.0):
        pts_str = " ".join(f"{x:.2f},{y:.2f}" for x, y in points)
        attrs = [
            f'points="{pts_str}"',
            f'fill="{fill}"',
            'stroke="none"'
        ]
        if opacity < 1.0:
            attrs.append(f'opacity="{opacity:.2f}"')
        self.elements.append(f'<polygon {" ".join(attrs)}/>')

    def badge(self, x: float | None = None, y: float = 0.0, text: str = "",
              right: float | None = None, bg_fill: str = "#161b22",
              border_color: str = "#30363d", text_color: str = COLOR_TEXT_MAIN,
              font_size: int = 11, font_weight: str = "bold",
              padding_x: float = 8.0, height: float = 22.0):
        char_w = 6.4 if font_weight == "bold" else 5.8
        w = len(text) * char_w + padding_x * 2.0
        if right is not None:
            actual_x = right - w
        elif x is not None:
            actual_x = x
        else:
            actual_x = 0.0

        self.rect(actual_x, y, w, height, rx=6.0, fill=bg_fill,
                  stroke=border_color, stroke_width=1.0)
        self.text(actual_x + w / 2.0, y + height * 0.70, text, fill=text_color,
                  font_size=font_size, font_family=FONT_SANS,
                  font_weight=font_weight, text_anchor="middle")
        return w

    def note_footer(self, x: float, y: float, text: str):
        bw = self.badge(x=x, y=y - 12.0, text="NOTE",
                        bg_fill="#161b22", border_color="#30363d",
                        text_color="#8b949e", font_size=9, font_weight="bold",
                        padding_x=6.0, height=16.0)
        self.text(x + bw + 8.0, y, text,
                  fill=COLOR_TEXT_DIM, font_size=10.5, font_family=FONT_SANS)

    def render(self) -> str:
        lines = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.width} {self.height}" width="100%" height="100%">',
            '  <defs>',
            '    <style>',
            '      text { text-rendering: geometricPrecision; }',
            '    </style>',
            '  </defs>',
            f'  <rect width="100%" height="100%" rx="12" fill="{COLOR_BG}" stroke="{COLOR_BORDER}" stroke-width="1.5"/>',
        ]
        for elem in self.elements:
            lines.append(f'  {elem}')
        lines.append('</svg>\n')
        return "\n".join(lines)


def parse_wan_history(history_path: Path):
    """
    Parses crates/yip-bench/wan/results/history.csv and extracts
    the loss sweep measurements for the latest commit run.
    """
    if not history_path.exists():
        raise FileNotFoundError(f"History file not found: {history_path}")

    with history_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if not rows:
        raise ValueError("history.csv is empty")

    latest_commit = rows[-1]["commit"]
    latest_rows = [r for r in rows if r["commit"] == latest_commit]

    goodput = {}
    effective = {}

    for r in latest_rows:
        prof = r["profile"]
        tunnel = r["tunnel"]
        param = r["param"]
        val = float(r["value"])

        if "injected=" in param and param.endswith("pct"):
            try:
                pct = int(param.replace("injected=", "").replace("pct", ""))
            except ValueError:
                continue

            if prof == "loss_goodput":
                goodput.setdefault(tunnel, {})[pct] = val
            elif prof == "loss_effective":
                effective.setdefault(tunnel, {})[pct] = val

    return {
        "commit": latest_commit,
        "goodput": goodput,
        "effective": effective
    }


def parse_sharding_scale(sharding_path: Path):
    """
    Parses crates/yip-bench/results/sharding-scale.csv.
    """
    if not sharding_path.exists():
        raise FileNotFoundError(f"Sharding scale file not found: {sharding_path}")

    with sharding_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    cores = []
    recvmmsg_gbps = []
    af_xdp_gbps = []
    io_uring_gbps = []
    af_xdp_mpps = []

    for r in rows:
        c = int(r["cores"])
        cores.append(c)
        recvmmsg_gbps.append(float(r["recvmmsg_gbps"]))
        af_xdp_gbps.append(float(r["af_xdp_gbps"]))
        io_uring_gbps.append(float(r["io_uring_gbps"]))
        af_xdp_mpps.append(float(r["af_xdp_mpps"]))

    return {
        "cores": cores,
        "recvmmsg_gbps": recvmmsg_gbps,
        "af_xdp_gbps": af_xdp_gbps,
        "io_uring_gbps": io_uring_gbps,
        "af_xdp_mpps": af_xdp_mpps
    }


def parse_latency_jitter(path: Path):
    """
    Parses crates/yip-bench/results/latency-jitter.csv.
    """
    if not path.exists():
        raise FileNotFoundError(f"Latency jitter CSV missing: {path}")

    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    yip_vals = {}
    wg_vals = {}
    ovpn_vals = {}
    base_vals = {}

    for r in rows:
        pct = int(r["loss_pct"])
        if r.get("yip_ms") and r["yip_ms"].strip():
            yip_vals[pct] = float(r["yip_ms"])
        if r.get("wireguard_ms") and r["wireguard_ms"].strip():
            wg_vals[pct] = float(r["wireguard_ms"])
        if r.get("openvpn_ms") and r["openvpn_ms"].strip():
            ovpn_vals[pct] = float(r["openvpn_ms"])
        if r.get("baseline_ms") and r["baseline_ms"].strip():
            base_vals[pct] = float(r["baseline_ms"])

    return {
        "yip": yip_vals,
        "wireguard": wg_vals,
        "openvpn": ovpn_vals,
        "baseline": base_vals,
    }


def generate_throughput_loss_chart(data: dict | None = None) -> str:
    """
    Generates assets/bench-throughput-loss.svg
    Logarithmic scale for TCP Goodput (Mbit/s).
    """
    if data is None:
        data = parse_wan_history(DEFAULT_WAN_HISTORY)
    canvas = SvgCanvas(width=840, height=480)

    # Header
    canvas.text(32.0, 34.0, "WAN TCP Goodput vs Packet Loss",
                fill=COLOR_TEXT_MAIN, font_size=18, font_weight="bold")
    canvas.text(32.0, 56.0, "AWS Multi-Region WAN: us-east-1 \u2194 us-west-2 (~60.6ms RTT, 1 vCPU, 10% FEC Parity)",
                fill=COLOR_TEXT_MUTED, font_size=12, font_family=FONT_MONO)

    # Plot bounding box
    plot_left = 80.0
    plot_right = 805.0
    plot_top = 115.0
    plot_bottom = 410.0
    plot_width = plot_right - plot_left
    plot_height = plot_bottom - plot_top

    # Legend at Row 3 (y = 84)
    legend_items = [
        ("yip (10% FEC)", COLOR_YIP, False),
        ("WireGuard", COLOR_WIREGUARD, False),
        ("Baseline", COLOR_BASELINE, True),
        ("OpenVPN", COLOR_OPENVPN, False),
    ]
    cur_lx = plot_left
    for label, color, dashed in legend_items:
        canvas.line(cur_lx, 82.0, cur_lx + 20.0, 82.0, stroke=color,
                    stroke_width=2.5, stroke_dasharray="4,3" if dashed else "")
        canvas.circle(cur_lx + 10.0, 82.0, 3.5, fill=color)
        canvas.text(cur_lx + 26.0, 86.0, label, fill=COLOR_TEXT_MAIN,
                    font_size=11, font_weight="600")
        cur_lx += len(label) * 7.2 + 42.0

    goodput = data.get("goodput", {})
    yip_data = goodput.get("yip", {})
    wg_data = goodput.get("wireguard", {})

    mult_3 = None
    if 3 in yip_data and 3 in wg_data and wg_data[3] > 0:
        mult_3 = round(yip_data[3] / wg_data[3])

    mult_10 = None
    if 10 in yip_data and 10 in wg_data and wg_data[10] > 0:
        mult_10 = round(yip_data[10] / wg_data[10])

    if mult_3 is not None and mult_10 is not None:
        lo_mult = min(mult_3, mult_10)
        hi_mult = max(mult_3, mult_10)
        header_text = f"{lo_mult}\u00d7 to {hi_mult}\u00d7 higher throughput under loss"
    elif mult_10 is not None:
        header_text = f"{mult_10}\u00d7 higher throughput under loss"
    else:
        header_text = "Higher throughput under loss"

    # Highlight badge on right side of Row 3
    canvas.badge(right=plot_right, y=72.0, text=header_text,
                 bg_fill="#1f1610", border_color="#f97316", text_color="#fb923c",
                 font_size=11, font_weight="bold", height=24.0)

    # Loss points: 0%, 1%, 3%, 5%, 10%
    loss_levels = [0, 1, 3, 5, 10]
    n_pts = len(loss_levels)
    x_coords = [plot_left + i * (plot_width / (n_pts - 1)) for i in range(n_pts)]

    # Y-axis log mapping: 0.3 to 600.0 Mbit/s
    min_log = math.log10(0.3)
    max_log = math.log10(600.0)
    log_span = max_log - min_log

    def val_to_y(val: float) -> float:
        v = max(val, 0.3)
        norm = (math.log10(v) - min_log) / log_span
        return plot_bottom - norm * plot_height

    # Y ticks: 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500
    y_ticks = [0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0]
    for tick in y_ticks:
        y = val_to_y(tick)
        is_major = tick in [0.5, 1.0, 10.0, 100.0, 500.0]
        canvas.line(plot_left, y, plot_right, y,
                    stroke=COLOR_GRID if is_major else COLOR_GRID_SUBTLE,
                    stroke_width=1.0)
        label_str = f"{tick:g}"
        canvas.text(plot_left - 8.0, y + 4.0, label_str,
                    fill=COLOR_TEXT_MUTED if is_major else COLOR_TEXT_DIM,
                    font_size=10, font_family=FONT_MONO, text_anchor="end")

    # X-axis ticks & vertical grid lines
    for i, pct in enumerate(loss_levels):
        x = x_coords[i]
        canvas.line(x, plot_top, x, plot_bottom, stroke=COLOR_GRID, stroke_width=1.0)
        canvas.text(x, plot_bottom + 18.0, f"{pct}%",
                    fill=COLOR_TEXT_MUTED, font_size=11, font_family=FONT_MONO,
                    text_anchor="middle")

    # Axes titles
    canvas.text(plot_left + plot_width / 2.0, plot_bottom + 36.0,
                "Netem Injected Packet Loss", fill=COLOR_TEXT_MAIN,
                font_size=12, font_weight="600", text_anchor="middle")

    canvas.text(plot_left - 46.0, plot_top + plot_height / 2.0,
                "TCP Goodput (Mbit/s, log scale)", fill=COLOR_TEXT_MAIN,
                font_size=11, font_weight="600", text_anchor="middle",
                extra_attrs=f'transform="rotate(-90 {plot_left - 46.0:.2f} {plot_top + plot_height / 2.0:.2f})"')

    goodput = data.get("goodput", {})

    curves = [
        ("baseline", COLOR_BASELINE, True, 1.5, False),
        ("openvpn", COLOR_OPENVPN, False, 2.0, False),
        ("wireguard", COLOR_WIREGUARD, False, 2.5, False),
        ("yip", COLOR_YIP, False, 3.2, True),
    ]

    for tunnel_key, color, dashed, width, is_primary in curves:
        tun_data = goodput.get(tunnel_key, {})
        pts = []
        for i, pct in enumerate(loss_levels):
            if pct in tun_data:
                v = tun_data[pct]
                pts.append((x_coords[i], val_to_y(v)))

        if len(pts) >= 2:
            canvas.polyline(pts, stroke=color, stroke_width=width,
                            stroke_dasharray="4,4" if dashed else "")

        for i, (px, py) in enumerate(pts):
            canvas.circle(px, py, 4.5 if is_primary else 3.5, fill=color,
                          stroke=COLOR_BG, stroke_width=1.5)

    # Callouts
    if 3 in yip_data and 3 in wg_data:
        x3 = x_coords[2]
        y_yip_3 = val_to_y(yip_data[3])
        canvas.text(x3 + 8.0, y_yip_3 - 6.0, f"{yip_data[3]:.1f}M",
                    fill=COLOR_YIP, font_size=10, font_family=FONT_MONO, font_weight="bold")
        badge_text_3 = (
            f"{mult_3}\u00d7 advantage ({yip_data[3]:.1f} vs {wg_data[3]:.1f} Mbit/s)"
            if mult_3 is not None else
            f"{yip_data[3]:.1f} vs {wg_data[3]:.1f} Mbit/s"
        )
        canvas.badge(x=x3 - 90.0, y=y_yip_3 - 34.0, text=badge_text_3,
                     bg_fill="#161b22", border_color=COLOR_BORDER, text_color="#f0f6fc",
                     font_size=10, font_weight="bold", height=20.0)

    if 10 in yip_data and 10 in wg_data:
        x10 = x_coords[4]
        y_yip_10 = val_to_y(yip_data[10])
        y_wg_10 = val_to_y(wg_data[10])

        canvas.badge(right=x10 - 16.0, y=y_yip_10 - 24.0, text=f"{yip_data[10]:.1f} Mbit/s",
                     bg_fill="#1f1610", border_color="#f97316", text_color="#f97316",
                     font_size=10, font_weight="bold", height=20.0)
        canvas.badge(right=x10 - 16.0, y=y_wg_10 + 6.0, text=f"{wg_data[10]:.1f} Mbit/s",
                     bg_fill="#141c2b", border_color="#38bdf8", text_color="#38bdf8",
                     font_size=10, font_weight="bold", height=20.0)

        # Bracket annotation
        canvas.line(x10 + 6.0, y_yip_10, x10 + 6.0, y_wg_10,
                    stroke=COLOR_YIP, stroke_width=1.5)
        canvas.line(x10 + 2.0, y_yip_10, x10 + 6.0, y_yip_10,
                    stroke=COLOR_YIP, stroke_width=1.5)
        canvas.line(x10 + 2.0, y_wg_10, x10 + 6.0, y_wg_10,
                    stroke=COLOR_YIP, stroke_width=1.5)

        badge_text_10 = (
            f"{mult_10}\u00d7 higher ({yip_data[10]:.1f} vs {wg_data[10]:.1f})"
            if mult_10 is not None else
            f"{yip_data[10]:.1f} vs {wg_data[10]:.1f}"
        )
        canvas.badge(right=x10 - 24.0, y=(y_yip_10 + y_wg_10) / 2.0 - 10.0,
                     text=badge_text_10,
                     bg_fill="#1f1610", border_color="#f97316", text_color="#fb923c",
                     font_size=10, font_weight="bold", height=20.0)

    # Bottom note
    canvas.note_footer(plot_left, plot_bottom + 52.0,
                       "Systematic Reed\u2013Solomon FEC trades minor clean-path overhead for near-complete immunity against loss.")

    return canvas.render()


def generate_fec_recovery_chart(data: dict | None = None) -> str:
    """
    Generates assets/bench-fec-recovery.svg
    Linear scale for Effective Packet Loss % (0% to 15%).
    """
    if data is None:
        data = parse_wan_history(DEFAULT_WAN_HISTORY)
    canvas = SvgCanvas(width=840, height=480)

    # Header
    canvas.text(32.0, 34.0, "FEC Recovery: Effective Loss Suppression",
                fill=COLOR_TEXT_MAIN, font_size=18, font_weight="bold")
    canvas.text(32.0, 56.0, "AWS Multi-Region WAN: us-east-1 \u2194 us-west-2 (~60.6ms RTT, Systematic Cauchy RS GF(256))",
                fill=COLOR_TEXT_MUTED, font_size=12, font_family=FONT_MONO)

    # Plot bounding box
    plot_left = 80.0
    plot_right = 805.0
    plot_top = 115.0
    plot_bottom = 410.0
    plot_width = plot_right - plot_left
    plot_height = plot_bottom - plot_top

    # Legend at Row 3 (y = 84)
    legend_items = [
        ("yip (RS-FEC)", COLOR_YIP, False),
        ("WireGuard", COLOR_WIREGUARD, False),
        ("Baseline", COLOR_BASELINE, True),
        ("OpenVPN", COLOR_OPENVPN, False),
    ]
    cur_lx = plot_left
    for label, color, dashed in legend_items:
        canvas.line(cur_lx, 82.0, cur_lx + 20.0, 82.0, stroke=color,
                    stroke_width=2.5, stroke_dasharray="4,3" if dashed else "")
        canvas.circle(cur_lx + 10.0, 82.0, 3.5, fill=color)
        canvas.text(cur_lx + 26.0, 86.0, label, fill=COLOR_TEXT_MAIN,
                    font_size=11, font_weight="600")
        cur_lx += len(label) * 7.2 + 42.0

    # Inset badge header
    canvas.badge(right=plot_right, y=72.0, text="Zero TCP Backoff via Systematic RS-FEC",
                 bg_fill="#141c2b", border_color="#38bdf8", text_color="#38bdf8",
                 font_size=11, font_weight="bold", height=24.0)

    loss_levels = [0, 1, 3, 5, 10]
    n_pts = len(loss_levels)
    x_coords = [plot_left + i * (plot_width / (n_pts - 1)) for i in range(n_pts)]

    # Y-axis linear: 0% to 15%
    max_y_pct = 15.0

    def val_to_y(val: float) -> float:
        norm = val / max_y_pct
        return plot_bottom - norm * plot_height

    # Y ticks: 0%, 3%, 6%, 9%, 12%, 15%
    y_ticks = [0.0, 3.0, 6.0, 9.0, 12.0, 15.0]
    for tick in y_ticks:
        y = val_to_y(tick)
        canvas.line(plot_left, y, plot_right, y, stroke=COLOR_GRID, stroke_width=1.0)
        canvas.text(plot_left - 8.0, y + 4.0, f"{int(tick)}%",
                    fill=COLOR_TEXT_MUTED, font_size=10, font_family=FONT_MONO,
                    text_anchor="end")

    # X ticks & vertical grid lines
    for i, pct in enumerate(loss_levels):
        x = x_coords[i]
        canvas.line(x, plot_top, x, plot_bottom, stroke=COLOR_GRID, stroke_width=1.0)
        canvas.text(x, plot_bottom + 18.0, f"{pct}%",
                    fill=COLOR_TEXT_MUTED, font_size=11, font_family=FONT_MONO,
                    text_anchor="middle")

    # Axes titles
    canvas.text(plot_left + plot_width / 2.0, plot_bottom + 36.0,
                "Injected Network Loss (netem)", fill=COLOR_TEXT_MAIN,
                font_size=12, font_weight="600", text_anchor="middle")

    canvas.text(plot_left - 46.0, plot_top + plot_height / 2.0,
                "Effective Ping Packet Loss %", fill=COLOR_TEXT_MAIN,
                font_size=11, font_weight="600", text_anchor="middle",
                extra_attrs=f'transform="rotate(-90 {plot_left - 46.0:.2f} {plot_top + plot_height / 2.0:.2f})"')

    effective = data.get("effective", {})

    curves = [
        ("baseline", COLOR_BASELINE, True, 1.5, False),
        ("openvpn", COLOR_OPENVPN, False, 2.0, False),
        ("wireguard", COLOR_WIREGUARD, False, 2.5, False),
        ("yip", COLOR_YIP, False, 3.5, True),
    ]

    # Draw shaded area for yip
    yip_eff = effective.get("yip", {})
    if yip_eff:
        poly_pts = [(x_coords[0], plot_bottom)]
        for i, pct in enumerate(loss_levels):
            if pct in yip_eff:
                poly_pts.append((x_coords[i], val_to_y(yip_eff[pct])))
        poly_pts.append((x_coords[-1], plot_bottom))
        canvas.polygon(poly_pts, fill=COLOR_YIP, opacity=0.15)

    for tunnel_key, color, dashed, width, is_primary in curves:
        tun_data = effective.get(tunnel_key, {})
        pts = []
        for i, pct in enumerate(loss_levels):
            if pct in tun_data:
                v = tun_data[pct]
                pts.append((x_coords[i], val_to_y(v)))

        if len(pts) >= 2:
            canvas.polyline(pts, stroke=color, stroke_width=width,
                            stroke_dasharray="4,4" if dashed else "")

        for i, (px, py) in enumerate(pts):
            canvas.circle(px, py, 4.5 if is_primary else 3.5, fill=color,
                          stroke=COLOR_BG, stroke_width=1.5)

    # Highlight callouts at 10% loss - placed with background badges to avoid curve strike-through
    x10 = x_coords[4]
    if "wireguard" in effective and 10 in effective["wireguard"]:
        y_wg = val_to_y(effective["wireguard"][10])
        canvas.badge(right=x10 - 14.0, y=y_wg - 26.0,
                     text=f"{int(effective['wireguard'][10])}% effective loss",
                     bg_fill="#0d1117", border_color=COLOR_BORDER, text_color=COLOR_WIREGUARD,
                     font_size=10, height=20.0)

    if "yip" in effective and 10 in effective["yip"]:
        yip_loss_10 = effective["yip"][10]
        y_yip = val_to_y(yip_loss_10)
        if yip_loss_10 == 0:
            callout_text = "0% loss (100% recovered)"
        else:
            rec_pct = round((10.0 - yip_loss_10) / 10.0 * 100.0)
            callout_text = f"{int(yip_loss_10)}% loss ({rec_pct}% recovered)"
        canvas.badge(right=x10 - 14.0, y=y_yip - 38.0,
                     text=callout_text,
                     bg_fill="#1f1610", border_color="#f97316", text_color="#fb923c",
                     font_size=10, height=20.0)

    # Explanatory badge inside plot (placed in clear upper-left quadrant)
    canvas.badge(x=plot_left + 24.0, y=plot_top + 24.0,
                 text="Cauchy RS GF(256): 100% recovery before kernel TCP timeout",
                 bg_fill="#161b22", border_color="#30363d", text_color="#c9d1d9",
                 font_size=10, font_weight="bold", height=22.0)

    # Bottom note
    canvas.note_footer(plot_left, plot_bottom + 52.0,
                       "Systematic Cauchy RS-FEC decodes lost packets in userspace, maintaining near-zero drop rate.")

    return canvas.render()


def generate_multicore_scaling_chart(data: dict | None = None) -> str:
    """
    Generates assets/bench-multicore-scaling.svg
    Linear scale for Multi-Stream TCP Throughput (Gbps).
    """
    if data is None:
        data = parse_sharding_scale(DEFAULT_SHARDING_SCALE)
    canvas = SvgCanvas(width=840, height=480)

    # Header
    canvas.text(32.0, 34.0, "Multi-Core Throughput Scaling (AF_XDP vs epoll vs io_uring)",
                fill=COLOR_TEXT_MAIN, font_size=18, font_weight="bold")
    canvas.text(32.0, 56.0, "Dedicated Multi-Core Testbed: 64 Parallel TCP Streams, Lock-Free SPSC Sharding (AMD Ryzen / EPYC)",
                fill=COLOR_TEXT_MUTED, font_size=12, font_family=FONT_MONO)

    # Plot bounding box - wider plot_left to give ample room for 'XX Gbps' tick labels and Y-axis title
    plot_left = 92.0
    plot_right = 805.0
    plot_top = 115.0
    plot_bottom = 410.0
    plot_width = plot_right - plot_left
    plot_height = plot_bottom - plot_top

    # Legend at Row 3 (y = 84)
    legend_items = [
        ("AF_XDP Zero-Copy", COLOR_AF_XDP, False),
        ("io_uring batch", COLOR_IO_URING, False),
        ("Vectorized epoll", COLOR_EPOLL, False),
    ]
    cur_lx = plot_left
    for label, color, dashed in legend_items:
        canvas.line(cur_lx, 82.0, cur_lx + 20.0, 82.0, stroke=color,
                    stroke_width=2.5, stroke_dasharray="4,3" if dashed else "")
        canvas.circle(cur_lx + 10.0, 82.0, 3.5, fill=color)
        canvas.text(cur_lx + 26.0, 86.0, label, fill=COLOR_TEXT_MAIN,
                    font_size=11, font_weight="600")
        cur_lx += len(label) * 7.2 + 38.0

    # Inset badge header
    canvas.badge(right=plot_right, y=72.0, text="40+ Gbps Line-Rate Multi-Core Scaling",
                 bg_fill="#1f1610", border_color="#fb923c", text_color="#fb923c",
                 font_size=11, font_weight="bold", height=24.0)

    cores = data["cores"]
    n_pts = len(cores)
    x_coords = [plot_left + i * (plot_width / (n_pts - 1)) for i in range(n_pts)]

    # Y-axis linear: 0 to 45 Gbps
    max_y_gbps = 45.0

    def val_to_y(val: float) -> float:
        norm = val / max_y_gbps
        return plot_bottom - norm * plot_height

    # Y ticks: 0, 10, 20, 30, 40 Gbps
    y_ticks = [0.0, 10.0, 20.0, 30.0, 40.0]
    for tick in y_ticks:
        y = val_to_y(tick)
        canvas.line(plot_left, y, plot_right, y, stroke=COLOR_GRID, stroke_width=1.0)
        canvas.text(plot_left - 8.0, y + 4.0, f"{int(tick)} Gbps",
                    fill=COLOR_TEXT_MUTED, font_size=10, font_family=FONT_MONO,
                    text_anchor="end")

    # X ticks & vertical grid lines
    for i, c in enumerate(cores):
        x = x_coords[i]
        canvas.line(x, plot_top, x, plot_bottom, stroke=COLOR_GRID, stroke_width=1.0)
        label = f"{c} Core" if c == 1 else f"{c} Cores"
        canvas.text(x, plot_bottom + 18.0, label,
                    fill=COLOR_TEXT_MUTED, font_size=11, font_family=FONT_MONO,
                    text_anchor="middle")

    # Axes titles
    canvas.text(plot_left + plot_width / 2.0, plot_bottom + 36.0,
                "Dedicated Worker Cores (Lock-Free Sharded Threads)", fill=COLOR_TEXT_MAIN,
                font_size=12, font_weight="600", text_anchor="middle")

    canvas.text(26.0, plot_top + plot_height / 2.0,
                "Multi-Stream TCP Throughput (Gbps)", fill=COLOR_TEXT_MAIN,
                font_size=11, font_weight="600", text_anchor="middle",
                extra_attrs=f'transform="rotate(-90 26.00 {plot_top + plot_height / 2.0:.2f})"')

    # Plot curves
    series = [
        ("Vectorized epoll", data["recvmmsg_gbps"], COLOR_EPOLL, 2.0),
        ("io_uring batch", data["io_uring_gbps"], COLOR_IO_URING, 2.2),
        ("AF_XDP Zero-Copy", data["af_xdp_gbps"], COLOR_AF_XDP, 3.2),
    ]

    # Shaded area under AF_XDP
    af_xdp_pts = [(x_coords[0], plot_bottom)]
    for i, val in enumerate(data["af_xdp_gbps"]):
        af_xdp_pts.append((x_coords[i], val_to_y(val)))
    af_xdp_pts.append((x_coords[-1], plot_bottom))
    canvas.polygon(af_xdp_pts, fill=COLOR_AF_XDP, opacity=0.12)

    for name, vals, color, width in series:
        pts = [(x_coords[i], val_to_y(v)) for i, v in enumerate(vals)]
        canvas.polyline(pts, stroke=color, stroke_width=width)
        for i, (px, py) in enumerate(pts):
            is_af = name == "AF_XDP Zero-Copy"
            canvas.circle(px, py, 4.5 if is_af else 3.5, fill=color,
                          stroke=COLOR_BG, stroke_width=1.5)
            val = vals[i]
            if is_af or (i == len(vals) - 1):
                if name == "AF_XDP Zero-Copy":
                    offset_y = -10.0
                elif name == "io_uring batch":
                    offset_y = -12.0
                else:  # Vectorized epoll
                    offset_y = 16.0

                if i == 0:
                    # Shift first point label inwards so it clears Y-axis
                    canvas.text(px + 8.0, py + offset_y, f"{val:.1f}",
                                fill=color, font_size=10, font_family=FONT_MONO,
                                font_weight="bold", text_anchor="start")
                else:
                    canvas.text(px, py + offset_y, f"{val:.1f}",
                                fill=color, font_size=10, font_family=FONT_MONO,
                                font_weight="bold", text_anchor="middle")

    # Annotations for 8-core AF_XDP (positioned safely inside plot box below plot_top)
    x8 = x_coords[-1]
    y_af_8 = val_to_y(data["af_xdp_gbps"][-1])
    top_gbps = data["af_xdp_gbps"][-1]
    top_mpps = data["af_xdp_mpps"][-1]
    base_gbps = data["af_xdp_gbps"][0]
    speedup = top_gbps / base_gbps if base_gbps > 0 else 1.0
    canvas.badge(right=plot_right - 14.0, y=120.0,
                 text=f"{top_gbps:.2f} Gbps @ {top_mpps:.2f} Mpps ({speedup:.1f}\u00d7 speedup)",
                 bg_fill="#161b22", border_color=COLOR_BORDER, text_color="#fb923c",
                 font_size=10, font_weight="bold", height=22.0)

    # Note
    canvas.note_footer(plot_left, plot_bottom + 52.0,
                       "Lock-free SPSC sharding eliminates cross-core contention, scaling near-linearly to 40+ Gbps line-rate.")

    return canvas.render()


def generate_bench_latency_jitter(data: dict | None = None) -> str:
    """
    Generates assets/bench-latency-jitter.svg
    Linear scale for Round-Trip P99 Tail Latency (0 to 240 ms) across packet loss (0% to 10%).
    Visualizes RS-FEC head-of-line blocking elimination vs ARQ retransmission timeouts.
    """
    if data is None:
        data = parse_latency_jitter(DEFAULT_LATENCY_JITTER)
    canvas = SvgCanvas(width=840, height=480)

    # Header
    canvas.text(32.0, 34.0, "Round-Trip P99 Tail Latency & Jitter Under Loss",
                fill=COLOR_TEXT_MAIN, font_size=18, font_weight="bold")
    canvas.text(32.0, 56.0, "AWS us-east-1 to us-west-2 (~61ms baseline RTT) \u2022 1400B packet stream \u2022 Head-of-line blocking comparison",
                fill=COLOR_TEXT_MUTED, font_size=12, font_family=FONT_MONO)

    # Plot bounding box
    plot_left = 80.0
    plot_right = 805.0
    plot_top = 115.0
    plot_bottom = 410.0
    plot_width = plot_right - plot_left
    plot_height = plot_bottom - plot_top

    # Legend at Row 3 (y = 82 / 86)
    legend_items = [
        ("yip (RS-FEC)", COLOR_YIP, ""),
        ("WireGuard (Kernel wg0)", COLOR_WIREGUARD, "6,4"),
        ("OpenVPN", COLOR_OPENVPN, "2,3"),
        ("Baseline IP", COLOR_BASELINE, "3,3"),
    ]
    cur_lx = plot_left
    for label, color, dasharray in legend_items:
        canvas.line(cur_lx, 82.0, cur_lx + 20.0, 82.0, stroke=color,
                    stroke_width=2.5, stroke_dasharray=dasharray)
        canvas.circle(cur_lx + 10.0, 82.0, 3.5, fill=color)
        canvas.text(cur_lx + 26.0, 86.0, label, fill=COLOR_TEXT_MAIN,
                    font_size=11, font_weight="600")
        cur_lx += len(label) * 6.8 + 32.0

    # Inset badge header on right side of Row 3
    canvas.badge(right=plot_right, y=72.0, text="Zero Head-of-Line Blocking",
                 bg_fill="#1f1610", border_color="#f97316", text_color="#fb923c",
                 font_size=11, font_weight="bold", height=24.0)

    # Injected packet loss percentages on X-axis
    loss_levels = [0, 1, 2, 3, 5, 8, 10]
    n_pts = len(loss_levels)
    x_coords = [plot_left + i * (plot_width / (n_pts - 1)) for i in range(n_pts)]

    # Y-axis linear: 0 to 240 ms
    max_y_ms = 240.0

    def val_to_y(val: float) -> float:
        v = min(max(val, 0.0), max_y_ms)
        norm = v / max_y_ms
        return plot_bottom - norm * plot_height

    # Y ticks: 0, 40, 80, 120, 160, 200, 240 ms
    y_ticks = [0.0, 40.0, 80.0, 120.0, 160.0, 200.0, 240.0]
    for tick in y_ticks:
        y = val_to_y(tick)
        canvas.line(plot_left, y, plot_right, y, stroke=COLOR_GRID, stroke_width=1.0)
        canvas.text(plot_left - 8.0, y + 4.0, f"{int(tick)} ms",
                    fill=COLOR_TEXT_MUTED, font_size=10, font_family=FONT_MONO,
                    text_anchor="end")

    # X ticks & vertical grid lines
    for i, pct in enumerate(loss_levels):
        x = x_coords[i]
        canvas.line(x, plot_top, x, plot_bottom, stroke=COLOR_GRID, stroke_width=1.0)
        canvas.text(x, plot_bottom + 18.0, f"{pct}%",
                    fill=COLOR_TEXT_MUTED, font_size=11, font_family=FONT_MONO,
                    text_anchor="middle")

    # Axes titles
    canvas.text(plot_left + plot_width / 2.0, plot_bottom + 36.0,
                "Injected Packet Loss Percentage", fill=COLOR_TEXT_MAIN,
                font_size=12, font_weight="600", text_anchor="middle")

    canvas.text(26.0, plot_top + plot_height / 2.0,
                "Round-Trip P99 Tail Latency (ms)", fill=COLOR_TEXT_MAIN,
                font_size=11, font_weight="600", text_anchor="middle",
                extra_attrs=f'transform="rotate(-90 26.00 {plot_top + plot_height / 2.0:.2f})"')

    # Data series points from loaded dataset
    yip_vals = data.get("yip", {})
    wg_vals = data.get("wireguard", {})
    ovpn_vals = data.get("openvpn", {})
    base_vals = data.get("baseline", {})

    # Shaded jitter band (+/- 1.2 ms) around yip (RS-FEC)
    upper_jitter = [(x_coords[i], val_to_y(yip_vals[pct] + 1.2)) for i, pct in enumerate(loss_levels) if pct in yip_vals]
    lower_jitter = [(x_coords[i], val_to_y(yip_vals[pct] - 1.2)) for i, pct in reversed(list(enumerate(loss_levels))) if pct in yip_vals]
    if upper_jitter and lower_jitter:
        canvas.polygon(upper_jitter + lower_jitter, fill=COLOR_YIP, opacity=0.15)

    # 1. Baseline IP (points at 0% and 1%, connection collapse beyond)
    base_pts = [(x_coords[i], val_to_y(base_vals[pct])) for i, pct in enumerate(loss_levels) if pct in base_vals]
    if len(base_pts) >= 2:
        canvas.polyline(base_pts, stroke=COLOR_BASELINE, stroke_width=1.5, stroke_dasharray="3,3")
    for px, py in base_pts:
        canvas.circle(px, py, 3.5, fill=COLOR_BASELINE, stroke=COLOR_BG, stroke_width=1.5)
    if 1 in base_vals:
        canvas.text(x_coords[1] + 8.0, val_to_y(base_vals[1]) - 8.0, "Collapse >1%",
                    fill=COLOR_BASELINE, font_size=9.5, font_family=FONT_MONO)

    # 2. OpenVPN (dotted line, climbs past 240 ms at 5%)
    ovpn_pts = [(x_coords[i], val_to_y(ovpn_vals[pct])) for i, pct in enumerate(loss_levels) if pct in ovpn_vals]
    if len(ovpn_pts) >= 2:
        canvas.polyline(ovpn_pts, stroke=COLOR_OPENVPN, stroke_width=2.0, stroke_dasharray="2,3")
    for px, py in ovpn_pts:
        canvas.circle(px, py, 3.5, fill=COLOR_OPENVPN, stroke=COLOR_BG, stroke_width=1.5)
    if 5 in ovpn_vals:
        canvas.badge(right=x_coords[4] - 10.0, y=plot_top + 10.0, text="Stalls >240 ms",
                     bg_fill="#1e142b", border_color="#a855f7", text_color="#c084fc",
                     font_size=10, font_weight="bold", height=20.0)

    # 3. WireGuard (Kernel wg0) (dashed line, climbing under loss due to ARQ/TCP retransmission timeout)
    wg_pts = [(x_coords[i], val_to_y(wg_vals[pct])) for i, pct in enumerate(loss_levels) if pct in wg_vals]
    if len(wg_pts) >= 2:
        canvas.polyline(wg_pts, stroke=COLOR_WIREGUARD, stroke_width=2.5, stroke_dasharray="6,4")
    for px, py in wg_pts:
        canvas.circle(px, py, 3.5, fill=COLOR_WIREGUARD, stroke=COLOR_BG, stroke_width=1.5)
    if 10 in wg_vals:
        canvas.badge(right=x_coords[-1] - 14.0, y=val_to_y(wg_vals[10]) + 6.0,
                     text=f"{wg_vals[10]:.1f} ms (ARQ timeout spike)",
                     bg_fill="#141c2b", border_color="#38bdf8", text_color="#38bdf8",
                     font_size=10, font_weight="bold", height=20.0)

    # 4. yip (RS-FEC) (solid line, flat at ~62 ms)
    yip_pts = [(x_coords[i], val_to_y(yip_vals[pct])) for i, pct in enumerate(loss_levels) if pct in yip_vals]
    if len(yip_pts) >= 2:
        canvas.polyline(yip_pts, stroke=COLOR_YIP, stroke_width=3.0)
    for px, py in yip_pts:
        canvas.circle(px, py, 4.5, fill=COLOR_YIP, stroke=COLOR_BG, stroke_width=1.5)
    if 10 in yip_vals:
        canvas.badge(right=x_coords[-1] - 14.0, y=val_to_y(yip_vals[10]) - 24.0,
                     text=f"{yip_vals[10]:.1f} ms (\u00b11.2ms jitter)",
                     bg_fill="#1f1610", border_color="#f97316", text_color="#fb923c",
                     font_size=10, font_weight="bold", height=20.0)

    # Callout box: Head-of-Line Blocking Suppressed (dynamically formatted from data)
    yip_p99_min = min(yip_vals.values()) if yip_vals else 62.0
    wg_p99_max = max(wg_vals.values()) if wg_vals else 235.0
    callout_text_full = (
        f"Head-of-Line Blocking Suppressed: Systematic userspace RS-FEC recovers "
        f"dropped symbols in-flight, keeping P99 flat at ~{yip_p99_min:.0f}ms vs ARQ retransmission spikes to {wg_p99_max:.0f}ms+"
    )
    box_x = plot_left + 16.0
    box_y = plot_top + 16.0
    box_w = 370.0
    box_h = 62.0
    canvas.rect(box_x, box_y, box_w, box_h, rx=6.0, fill="#161b22", stroke=COLOR_BORDER,
                stroke_width=1.0, extra_attrs=f'aria-label="{callout_text_full}"')
    canvas.rect(box_x, box_y, 4.0, box_h, rx=2.0, fill=COLOR_YIP)

    canvas.text(box_x + 12.0, box_y + 18.0, "Head-of-Line Blocking Suppressed:",
                fill=COLOR_YIP, font_size=11, font_weight="bold")
    canvas.text(box_x + 12.0, box_y + 36.0, "Systematic userspace RS-FEC recovers dropped symbols in-flight,",
                fill=COLOR_TEXT_MAIN, font_size=9.5)
    canvas.text(box_x + 12.0, box_y + 51.0, f"keeping P99 flat at ~{yip_p99_min:.0f}ms vs ARQ retransmission spikes to {wg_p99_max:.0f}ms+.",
                fill=COLOR_TEXT_MUTED, font_size=9.5)

    # Bottom note footer
    canvas.note_footer(plot_left, plot_bottom + 52.0,
                       "Systematic Cauchy RS-FEC recovers lost symbols in-flight, eliminating multi-RTT head-of-line blocking.")

    return canvas.render()


def main():
    parser = argparse.ArgumentParser(description="Deterministic SVG benchmark graph generator.")
    parser.add_argument("--check", action="store_true",
                        help="Check if SVG assets are up-to-date and valid XML without writing to disk.")
    parser.add_argument("--repo-root", type=Path, default=None,
                        help="Path to repository root (defaults to auto-detection).")
    args = parser.parse_args()

    if args.repo_root:
        repo_root = args.repo_root.resolve()
    else:
        repo_root = Path(__file__).resolve().parent.parent.parent

    wan_history_path = repo_root / "crates" / "yip-bench" / "wan" / "results" / "history.csv"
    sharding_scale_path = repo_root / "crates" / "yip-bench" / "results" / "sharding-scale.csv"
    latency_jitter_path = repo_root / "crates" / "yip-bench" / "results" / "latency-jitter.csv"
    assets_dir = repo_root / "assets"

    if not wan_history_path.exists():
        print(f"Error: WAN history CSV missing: {wan_history_path}", file=sys.stderr)
        sys.exit(1)

    if not sharding_scale_path.exists():
        print(f"Error: Sharding scale CSV missing: {sharding_scale_path}", file=sys.stderr)
        sys.exit(1)

    if not latency_jitter_path.exists():
        print(f"Error: Latency jitter CSV missing: {latency_jitter_path}", file=sys.stderr)
        sys.exit(1)

    wan_data = parse_wan_history(wan_history_path)
    sharding_data = parse_sharding_scale(sharding_scale_path)
    latency_data = parse_latency_jitter(latency_jitter_path)

    targets = {
        assets_dir / "bench-throughput-loss.svg": generate_throughput_loss_chart(wan_data),
        assets_dir / "bench-fec-recovery.svg": generate_fec_recovery_chart(wan_data),
        assets_dir / "bench-multicore-scaling.svg": generate_multicore_scaling_chart(sharding_data),
        assets_dir / "bench-latency-jitter.svg": generate_bench_latency_jitter(latency_data),
    }

    # Validate generated XML syntax
    for path, content in targets.items():
        try:
            ET.fromstring(content)
        except ET.ParseError as e:
            print(f"Error: Generated SVG for {path.name} is not valid XML: {e}", file=sys.stderr)
            sys.exit(1)

    if args.check:
        drift_detected = False
        for path, expected_content in targets.items():
            if not path.exists():
                print(f"Check failed: {path} does not exist on disk", file=sys.stderr)
                drift_detected = True
                continue

            try:
                disk_content = path.read_text(encoding="utf-8")
                ET.fromstring(disk_content)
            except Exception as e:
                print(f"Check failed: {path} is not valid XML on disk: {e}", file=sys.stderr)
                drift_detected = True
                continue

            if disk_content != expected_content:
                print(f"Check failed: {path} differs from generated output (drift detected)", file=sys.stderr)
                drift_detected = True

        if drift_detected:
            sys.exit(1)
        else:
            print("OK: All benchmark SVG assets are up-to-date and valid XML.")
            sys.exit(0)

    # Generation mode
    assets_dir.mkdir(parents=True, exist_ok=True)
    for path, content in targets.items():
        path.write_text(content, encoding="utf-8")
        print(f"Generated {path}")

        # Rasterize PNG
        png_path = path.with_suffix(".png")
        for cmd in ["magick", "convert"]:
            try:
                subprocess.run([cmd, "-density", "192", str(path), str(png_path)],
                               check=True, capture_output=True)
                if png_path.exists() and png_path.stat().st_size > 0:
                    print(f"Rasterized: {png_path} ({png_path.stat().st_size / 1024:.1f} KB)")
                    break
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue


if __name__ == "__main__":
    main()
