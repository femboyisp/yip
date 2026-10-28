#!/usr/bin/env python3
"""
Unit tests for deterministic wire format diagram generator in crates/yip-bench.
"""

from importlib.machinery import SourceFileLoader
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

BENCH_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BENCH_DIR.parent.parent
sys.path.insert(0, str(BENCH_DIR))

generate_wire_format_module = SourceFileLoader(
    "generate_wire_format", str(BENCH_DIR / "generate-wire-format.py")
).load_module()


class TestWireFormatGenerator(unittest.TestCase):
    def test_wire_format_valid_xml(self):
        svg_str = generate_wire_format_module.generate_wire_format_svg()
        root = ET.fromstring(svg_str)
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
        self.assertEqual(root.attrib.get("viewBox"), "0 0 1040 820")
        self.assertEqual(root.attrib.get("width"), "1040")
        self.assertEqual(root.attrib.get("height"), "820")

    def test_wire_format_determinism(self):
        run1 = generate_wire_format_module.generate_wire_format_svg()
        run2 = generate_wire_format_module.generate_wire_format_svg()
        self.assertEqual(run1, run2)

    def test_theme_palette(self):
        svg_str = generate_wire_format_module.generate_wire_format_svg()
        # Canvas & Card theme
        self.assertIn("#0d1117", svg_str)  # COLOR_CANVAS_BG
        self.assertIn("#30363d", svg_str)  # COLOR_CANVAS_BORDER
        self.assertIn("#161b22", svg_str)  # COLOR_CARD_BG
        self.assertIn("#f0f6fc", svg_str)  # COLOR_TEXT_MAIN
        self.assertIn("#8b949e", svg_str)  # COLOR_TEXT_MUTED
        self.assertIn("#6e7681", svg_str)  # COLOR_TEXT_DIM

        # Domain colors
        self.assertIn("#f97316", svg_str)  # Fox orange
        self.assertIn("#fb923c", svg_str)  # Amber
        self.assertIn("#38bdf8", svg_str)  # Sky blue
        self.assertIn("#818cf8", svg_str)  # Indigo
        self.assertIn("#10b981", svg_str)  # Emerald green
        self.assertIn("#34d399", svg_str)  # Mint green
        self.assertIn("#a855f7", svg_str)  # Purple
        self.assertIn("#c084fc", svg_str)  # Light purple

    def test_top_header(self):
        svg_str = generate_wire_format_module.generate_wire_format_svg()
        self.assertIn("yip Wire Protocol &amp; Cryptographic Ceremony", svg_str)
        self.assertIn("Zero-Fixed-Signature Keyed Header Protection", svg_str)
        self.assertIn("Noise-IKpsk2 + ML-KEM-512 PQ Hybrid", svg_str)
        self.assertIn("120s Ratchet Overlap", svg_str)
        self.assertIn("Self-Certifying IPv6", svg_str)

    def test_panel_a_framing_and_dpi(self):
        svg_str = generate_wire_format_module.generate_wire_format_svg()
        self.assertIn("PANEL A", svg_str)
        self.assertIn("Data-Plane Datagram Framing", svg_str)
        self.assertIn("Bytes 0..15 (15B)", svg_str)
        self.assertIn("Masked Wire Header", svg_str)
        self.assertIn("SipHash-1-3 CTR Mask", svg_str)
        self.assertIn("Bytes (N-8)..N (8B)", svg_str)
        self.assertIn("Trailing Auth Tag", svg_str)
        self.assertIn("SipHash-1-3 Coverage MAC", svg_str)
        self.assertIn("Bytes 15..(N-8) (Variable MTU)", svg_str)
        self.assertIn("Encrypted Symbol Payload", svg_str)
        self.assertIn("conn_tag (8B / 64b)", svg_str)
        self.assertIn("object_id (2B / 16b)", svg_str)
        self.assertIn("payload_id (4B / 32b)", svg_str)
        self.assertIn("flags (1B / 8b)", svg_str)
        self.assertIn("Anti-DPI Guarantee: Zero Static Signatures", svg_str)
        self.assertIn("15B header protected by SipHash-1-3 CTR keystream", svg_str)

    def test_panel_b_post_quantum_handshake(self):
        svg_str = generate_wire_format_module.generate_wire_format_svg()
        self.assertIn("PANEL B", svg_str)
        self.assertIn("Post-Quantum Hybrid Handshake", svg_str)
        self.assertIn("Message 1 (Initiator → Responder) — 1,028 Bytes:", svg_str)
        self.assertIn("ek_A (800B ML-KEM-512 pk)", svg_str)
        self.assertIn("e_A (32B)", svg_str)
        self.assertIn("Enc(s_A ‖ Cert_A) + Tag", svg_str)
        self.assertIn("Message 2 (Responder → Initiator) — 948 Bytes:", svg_str)
        self.assertIn("ct (768B ML-KEM-512 ct)", svg_str)
        self.assertIn("e_B (32B)", svg_str)
        self.assertIn("Enc(Cert_B) + Tag", svg_str)
        self.assertIn("OBF_MTU_BUDGET", svg_str)
        self.assertIn("FIPS 203 §7.2", svg_str)
        self.assertIn("&lt; 3329", svg_str)
        self.assertIn("IND-CCA2", svg_str)
        self.assertIn("set_psk(2, &amp;ss)", svg_str)

    def test_panel_c_epoch_ratchet(self):
        svg_str = generate_wire_format_module.generate_wire_format_svg()
        self.assertIn("PANEL C", svg_str)
        self.assertIn("120s Epoch Ratchet Overlap", svg_str)
        self.assertIn("20s Overlap Window", svg_str)
        self.assertIn("Epoch N Active (TX + RX)", svg_str)
        self.assertIn("Epoch N+1 Active (TX + RX)", svg_str)
        self.assertIn("t = 110s", svg_str)
        self.assertIn("Rekey HS", svg_str)
        self.assertIn("t = 120s", svg_str)
        self.assertIn("Epoch End", svg_str)
        self.assertIn("t = 130s", svg_str)
        self.assertIn("Zeroize", svg_str)
        self.assertIn("Zeroize on Retire", svg_str)
        self.assertIn("0% Dropped Packets During Continuous Key Refresh", svg_str)

    def test_panel_d_node_addressing(self):
        svg_str = generate_wire_format_module.generate_wire_format_svg()
        self.assertIn("PANEL D", svg_str)
        self.assertIn("Cryptographic Node Addressing", svg_str)
        self.assertIn("fd00::/8", svg_str)
        self.assertIn("Ed25519 Identity", svg_str)
        self.assertIn("BLAKE2s-128", svg_str)
        self.assertIn("&quot;yip-node-v1&quot;", svg_str)
        self.assertIn("0xfd (8 bits)", svg_str)
        self.assertIn("Digest[0..7] (56 bits)", svg_str)
        self.assertIn("Digest[7..15] (64 bits)", svg_str)
        self.assertIn("Self-Certifying", svg_str)
        self.assertIn("Zero Central Infrastructure", svg_str)

    def test_cli_check_success(self):
        cmd = [sys.executable, str(BENCH_DIR / "generate-wire-format.py"), "--check"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"CLI --check failed: {res.stderr}")
        self.assertIn("OK: wire-format.svg is up-to-date and valid XML.", res.stdout)

    def test_cli_check_drift_detection(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".svg") as tmp:
            tmp.write("<svg><!-- modified --></svg>")
            tmp.flush()
            cmd = [sys.executable, str(BENCH_DIR / "generate-wire-format.py"), "--output", tmp.name, "--check"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(res.returncode, 1)
            self.assertIn("differs from generated output", res.stderr)


if __name__ == "__main__":
    unittest.main()
