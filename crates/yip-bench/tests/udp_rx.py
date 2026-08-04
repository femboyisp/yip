#!/usr/bin/env python3
# udp_rx.py <bind_ip> <port> <expect_n> <idle_timeout_s>
# Counts unique sequence numbers received; prints
#   received=<k> of <n> stop=<idle|complete> idle_gap=<s>
# stop=idle  -> the socket saw <idle_timeout_s> of silence and quit; the tail
#              may still have been arriving (receiver patience was the limit).
# stop=complete -> all <n> unique seqs arrived.
# idle_gap  -> seconds since the last packet at exit (~idle_timeout_s for an
#              idle stop). Diagnostic for the ARQ integrity test: it tells a
#              future failure whether the receiver gave up early on a slow
#              retransmit tail or the packets genuinely never came.
import socket, sys, time
ip, port, n, idle = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
s.bind((ip, port))
s.settimeout(idle)
seen = set()
last = time.monotonic()
stop = "idle"
try:
    while True:
        try:
            data, _ = s.recvfrom(2048)
        except socket.timeout:
            stop = "idle"
            break
        last = time.monotonic()
        if len(data) >= 4:
            seen.add(int.from_bytes(data[:4], "big"))
        if len(seen) >= n:
            stop = "complete"
            break
except KeyboardInterrupt:
    pass
gap = time.monotonic() - last
print(f"received={len(seen)} of {n} stop={stop} idle_gap={gap:.1f}")
