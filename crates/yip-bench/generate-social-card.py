#!/usr/bin/env python3
"""
generate-social-card.py

Generates 1280x640 social preview card for yip:
- assets/social-card.svg
- assets/social-card.png (< 1 MB)

Zero external pip dependencies for SVG; rasterizes via ImageMagick or PIL.
"""

from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

FONT_SANS = "ui-sans-serif, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
FONT_MONO = "ui-monospace, SFMono-Regular, Menlo, monospace"


def build_social_card_svg() -> str:
    w = 1280
    h = 640
    lines = []

    lines.append('<?xml version="1.0" encoding="UTF-8"?>')
    lines.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}">')
    lines.append('  <defs>')
    lines.append('    <style>')
    lines.append('      text { text-rendering: geometricPrecision; }')
    lines.append('    </style>')
    lines.append('    <linearGradient id="bg-grad" x1="0%" y1="0%" x2="100%" y2="100%">')
    lines.append('      <stop offset="0%" stop-color="#0d1117" />')
    lines.append('      <stop offset="100%" stop-color="#161b22" />')
    lines.append('    </linearGradient>')
    lines.append('    <linearGradient id="orange-grad" x1="0%" y1="0%" x2="100%" y2="0%">')
    lines.append('      <stop offset="0%" stop-color="#ea580c" />')
    lines.append('      <stop offset="100%" stop-color="#f97316" />')
    lines.append('    </linearGradient>')
    lines.append('    <linearGradient id="plot-fill" x1="0%" y1="0%" x2="0%" y2="100%">')
    lines.append('      <stop offset="0%" stop-color="#f97316" stop-opacity="0.25" />')
    lines.append('      <stop offset="100%" stop-color="#f97316" stop-opacity="0.0" />')
    lines.append('    </linearGradient>')
    lines.append('  </defs>')

    # Background card
    lines.append(f'  <rect width="{w}" height="{h}" fill="url(#bg-grad)" stroke="#30363d" stroke-width="2" rx="16" />')

    # Subtle ambient glow
    lines.append('  <circle cx="1100" cy="120" r="280" fill="#f97316" opacity="0.06" filter="blur(60px)" />')
    lines.append('  <circle cx="150" cy="520" r="240" fill="#38bdf8" opacity="0.04" filter="blur(60px)" />')

    # Brand Title Group
    lines.append('  <g id="brand" transform="translate(80, 110)">')
    # Fox Icon Badge (vector polygon + text)
    lines.append('    <rect x="0" y="0" width="112" height="42" rx="10" fill="#431407" stroke="#f97316" stroke-width="1.5" />')
    lines.append('    <polygon points="18,30 25,14 32,22 39,14 46,30 32,34" fill="#fb923c" />')
    lines.append(f'    <text x="74" y="28" font-family="{FONT_MONO}" font-size="18" font-weight="800" fill="#fb923c" text-anchor="middle">YIP</text>')

    # Main Hero Title
    lines.append(f'    <text x="136" y="32" font-family="{FONT_SANS}" font-size="38" font-weight="800" fill="#f0f6fc">yip mesh vpn</text>')
    
    # Tagline
    lines.append(f'    <text x="0" y="85" font-family="{FONT_SANS}" font-size="21" font-weight="500" fill="#c9d1d9">Loss-Immune Peer-to-Peer Mesh VPN in Rust</text>')
    lines.append(f'    <text x="0" y="118" font-family="{FONT_MONO}" font-size="14.5" fill="#8b949e">Systematic Cauchy RS-FEC (GF(256)) • 40 Gbps eBPF AF_XDP • Anti-DPI REALITY</text>')
    lines.append('  </g>')

    # Feature Badges (with inline vector icons instead of emojis)
    badges = [
        ("shield", "0% TCP Backoff Under Loss", "#1f1610", "#fb923c", "#f97316"),
        ("bolt", "40+ Gbps Multi-Core Line Rate", "#064e3b", "#34d399", "#10b981"),
        ("lock", "Noise-IK &amp; REALITY Anti-DPI", "#1e1b4b", "#818cf8", "#6366f1"),
        ("rust", "100% Rust • AGPL-3.0", "#161b22", "#e6edf3", "#30363d"),
    ]
    bx = 80
    by = 280
    for icon_type, text, bg, fg, border in badges:
        clean_text = text.replace("&amp;", "&")
        bw = 34 + len(clean_text) * 7.4 + 16
        lines.append(f'  <rect x="{bx}" y="{by}" width="{bw:.2f}" height="32" rx="16" fill="{bg}" stroke="{border}" stroke-width="1.2" />')
        
        # Render vector icon
        if icon_type == "shield":
            lines.append(f'  <path d="M {bx + 14},{by + 11} L {bx + 20},{by + 8} L {bx + 26},{by + 11} L {bx + 26},{by + 17} C {bx + 26},{by + 22} {bx + 20},{by + 25} {bx + 20},{by + 25} C {bx + 20},{by + 25} {bx + 14},{by + 22} {bx + 14},{by + 17} Z" fill="{fg}" />')
        elif icon_type == "bolt":
            lines.append(f'  <polygon points="{bx + 20},{by + 8} {bx + 13},{by + 16} {bx + 19},{by + 16} {bx + 16},{by + 24} {bx + 26},{by + 14} {bx + 20},{by + 14}" fill="{fg}" />')
        elif icon_type == "lock":
            lines.append(f'  <rect x="{bx + 15}" y="{by + 14}" width="12" height="9" rx="2" fill="{fg}" />')
            lines.append(f'  <path d="M {bx + 17},{by + 14} L {bx + 17},{by + 11} C {bx + 17},{by + 9} {bx + 19},{by + 8} {bx + 21},{by + 8} C {bx + 23},{by + 8} {bx + 25},{by + 9} {bx + 25},{by + 11} L {bx + 25},{by + 14}" stroke="{fg}" stroke-width="1.6" fill="none" />')
        elif icon_type == "rust":
            lines.append(f'  <circle cx="{bx + 21}" cy="{by + 16}" r="6" stroke="{fg}" stroke-width="1.6" fill="none" />')
            lines.append(f'  <circle cx="{bx + 21}" cy="{by + 16}" r="2.5" fill="{fg}" />')

        lines.append(f'  <text x="{bx + 32:.2f}" y="{by + 21}" font-family="{FONT_MONO}" font-size="12" font-weight="600" fill="{fg}">{text}</text>')
        bx += bw + 14

    # Visual Curve Preview Card (Right-hand Hero Graphic)
    lines.append('  <g id="mini-graph" transform="translate(80, 345)">')
    gw = 1120
    gh = 225
    lines.append(f'    <rect width="{gw}" height="{gh}" rx="12" fill="#0d1117" stroke="#30363d" stroke-width="1.2" />')
    
    # Graph title
    lines.append(f'    <text x="24" y="32" font-family="{FONT_SANS}" font-size="14" font-weight="700" fill="#f0f6fc">Throughput Under Network Packet Loss (AWS us-east-1 ↔ us-west-2, 60ms RTT)</text>')
    lines.append(f'    <text x="{gw - 24}" y="32" font-family="{FONT_MONO}" font-size="12" font-weight="700" fill="#fb923c" text-anchor="end">33× to 98× Higher Goodput at 3%–10% Loss</text>')
    
    # Simple stylised curves - ending at x=900 so labels at x=925 fit inside 1120 card
    # x: 0% (x=80), 1% (x=280), 3% (x=490), 5% (x=700), 10% (x=900)
    yip_pts = [(80, 65), (280, 75), (490, 85), (700, 105), (900, 140)]
    wg_pts = [(80, 55), (280, 120), (490, 180), (700, 186), (900, 190)]

    # Grid line
    lines.append('    <line x1="80" y1="190" x2="900" y2="190" stroke="#21262d" stroke-width="1" />')
    lines.append(f'    <text x="60" y="194" font-family="{FONT_MONO}" font-size="10" fill="#6e7681" text-anchor="end">0</text>')
    lines.append('    <line x1="80" y1="60" x2="900" y2="60" stroke="#21262d" stroke-width="1" stroke-dasharray="3,3" />')
    lines.append(f'    <text x="60" y="65" font-family="{FONT_MONO}" font-size="10" fill="#6e7681" text-anchor="end">400M</text>')

    # Shaded area under yip
    shade_pts = [(80, 190)] + yip_pts + [(900, 190)]
    shade_str = " ".join(f"{x},{y}" for x, y in shade_pts)
    lines.append(f'    <polygon points="{shade_str}" fill="url(#plot-fill)" />')

    # WireGuard curve
    wg_str = " ".join(f"{x},{y}" for x, y in wg_pts)
    lines.append(f'    <polyline points="{wg_str}" fill="none" stroke="#38bdf8" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" />')

    # yip curve
    yip_str = " ".join(f"{x},{y}" for x, y in yip_pts)
    lines.append(f'    <polyline points="{yip_str}" fill="none" stroke="#f97316" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" />')

    # Labels at end of curves (comfortably inside card)
    lines.append(f'    <text x="918" y="144" font-family="{FONT_MONO}" font-size="11.5" font-weight="700" fill="#f97316">yip (16.6 Mbit/s)</text>')
    lines.append(f'    <text x="918" y="194" font-family="{FONT_MONO}" font-size="11" font-weight="600" fill="#38bdf8">WireGuard (0.5 Mbit/s)</text>')

    # X-axis markers
    for x_pos, loss_lbl in [(80, "0% Loss"), (280, "1%"), (490, "3%"), (700, "5%"), (900, "10% Loss")]:
        lines.append(f'    <text x="{x_pos}" y="208" font-family="{FONT_MONO}" font-size="10" fill="#8b949e" text-anchor="middle">{loss_lbl}</text>')

    lines.append('  </g>')

    lines.append('</svg>')
    return "\n".join(lines) + "\n"


def main():
    repo_root = Path(__file__).resolve().parent.parent.parent
    assets_dir = repo_root / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)

    svg_path = assets_dir / "social-card.svg"
    png_path = assets_dir / "social-card.png"

    svg_content = build_social_card_svg()
    ET.fromstring(svg_content)  # Validate XML syntax
    svg_path.write_text(svg_content, encoding="utf-8")
    print(f"Generated: {svg_path}")

    # Rasterize to PNG (< 1 MB)
    rasterized = False
    for cmd in ["magick", "convert"]:
        try:
            subprocess.run([cmd, str(svg_path), str(png_path)], check=True, capture_output=True)
            if png_path.exists() and png_path.stat().st_size > 0:
                rasterized = True
                break
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

    if not rasterized:
        try:
            from PIL import Image, ImageDraw, ImageFont
            img = Image.new("RGBA", (1280, 640), "#0d1117")
            # Fallback PIL card
            d = ImageDraw.Draw(img)
            d.rectangle([(0, 0), (1279, 639)], outline="#30363d", width=2)
            d.text((80, 100), "🦊 yip mesh vpn", fill="#f0f6fc")
            d.text((80, 150), "Loss-Immune Peer-to-Peer Mesh VPN in Rust", fill="#c9d1d9")
            img.save(str(png_path), "PNG")
            rasterized = True
        except Exception as e:
            print(f"Warning: PNG rasterization failed: {e}", file=sys.stderr)

    if rasterized and png_path.exists():
        size_kb = png_path.stat().st_size / 1024
        print(f"Rasterized: {png_path} ({size_kb:.1f} KB)")
        assert size_kb < 1024, f"PNG exceeds 1 MB limit: {size_kb:.1f} KB"
    else:
        print("Warning: PNG was not generated", file=sys.stderr)


if __name__ == "__main__":
    main()
