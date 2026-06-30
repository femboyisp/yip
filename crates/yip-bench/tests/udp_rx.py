#!/usr/bin/env python3
# udp_rx.py <bind_ip> <port> <expect_n> <idle_timeout_s>
# Counts unique sequence numbers received; prints "received=<k> of <n>".
import socket, sys
ip, port, n, idle = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
s.bind((ip, port))
s.settimeout(idle)
seen = set()
try:
    while True:
        try:
            data, _ = s.recvfrom(2048)
        except socket.timeout:
            break
        if len(data) >= 4:
            seen.add(int.from_bytes(data[:4], "big"))
        if len(seen) >= n:
            break
except KeyboardInterrupt:
    pass
print(f"received={len(seen)} of {n}")
