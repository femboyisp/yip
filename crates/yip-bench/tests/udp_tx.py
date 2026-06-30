#!/usr/bin/env python3
# udp_tx.py <dst_ip> <port> <n> <pps> [payload_bytes]
# Sends n sequenced UDP packets at ~pps packets/sec.
import socket, sys, time
ip, port, n, pps = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
size = int(sys.argv[5]) if len(sys.argv) > 5 else 200
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 << 20)
interval = 1.0 / pps
pad = b"\x00" * max(0, size - 4)
t = time.perf_counter()
for i in range(n):
    s.sendto(i.to_bytes(4, "big") + pad, (ip, port))
    t += interval
    d = t - time.perf_counter()
    if d > 0:
        time.sleep(d)
print(f"sent={n}")
