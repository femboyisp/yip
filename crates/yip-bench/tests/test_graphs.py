#!/usr/bin/env python3
"""
Unit tests for deterministic graph generators in crates/yip-bench.
"""

import sys
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

# Add crates/yip-bench to sys.path
BENCH_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BENCH_DIR.parent.parent
sys.path.insert(0, str(BENCH_DIR))

from importlib.machinery import SourceFileLoader

generate_graphs_module = SourceFileLoader(
    "generate_graphs", str(BENCH_DIR / "generate-graphs.py")
).load_module()


class TestGraphGenerators(unittest.TestCase):
    def test_latency_jitter_valid_xml(self):
        svg_str = generate_graphs_module.generate_bench_latency_jitter()
        root = ET.fromstring(svg_str)
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
        self.assertEqual(root.attrib.get("viewBox"), "0 0 840 480")

    def test_latency_jitter_determinism(self):
        run1 = generate_graphs_module.generate_bench_latency_jitter()
        run2 = generate_graphs_module.generate_bench_latency_jitter()
        self.assertEqual(run1, run2)

    def test_latency_jitter_palette_and_elements(self):
        svg_str = generate_graphs_module.generate_bench_latency_jitter()
        # Colors
        self.assertIn("#0d1117", svg_str)  # COLOR_BG
        self.assertIn("#30363d", svg_str)  # COLOR_BORDER
        self.assertIn("#21262d", svg_str)  # COLOR_GRID
        self.assertIn("#f0f6fc", svg_str)  # COLOR_TEXT_MAIN
        self.assertIn("#8b949e", svg_str)  # COLOR_TEXT_MUTED
        self.assertIn("#f97316", svg_str)  # COLOR_YIP
        self.assertIn("#38bdf8", svg_str)  # COLOR_WIREGUARD
        self.assertIn("#a855f7", svg_str)  # COLOR_OPENVPN
        self.assertIn("#64748b", svg_str)  # COLOR_BASELINE

        # Title & Subtitle
        self.assertIn("Round-Trip P99 Tail Latency &amp; Jitter Under Loss", svg_str)
        self.assertIn("AWS us-east-1 to us-west-2 (~61ms baseline RTT)", svg_str)

        # Callout
        self.assertIn("Head-of-Line Blocking Suppressed", svg_str)
        self.assertIn("Systematic userspace RS-FEC recovers dropped symbols in-flight", svg_str)
        self.assertIn("keeping P99 flat at ~62ms vs ARQ retransmission spikes to 235ms+", svg_str)

        # Legend entries
        self.assertIn("yip (RS-FEC)", svg_str)
        self.assertIn("WireGuard (Kernel wg0)", svg_str)
        self.assertIn("OpenVPN", svg_str)
        self.assertIn("Baseline IP", svg_str)

        # Ticks
        for tick in ["0 ms", "40 ms", "80 ms", "120 ms", "160 ms", "200 ms", "240 ms"]:
            self.assertIn(tick, svg_str)

        for pct in ["0%", "1%", "2%", "3%", "5%", "8%", "10%"]:
            self.assertIn(f">{pct}<", svg_str)


if __name__ == "__main__":
    unittest.main()
