#!/usr/bin/env python3
"""Simple TCP listener for kshell_nacl.ko test — accepts and logs data."""

import socket
import sys
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 4444))
s.listen(1)
s.settimeout(20)
try:
    c, a = s.accept()
    sys.stdout.write("CONNECTED\n")
    sys.stdout.flush()
    time.sleep(3)
    data = c.recv(4096)
    sys.stdout.write("RECV_BYTES: " + str(len(data)) + "\n")
    if len(data) > 28:
        sys.stdout.write("ENCRYPTED_FRAME: yes\n")
    sys.stdout.flush()
    c.close()
except TimeoutError:
    sys.stdout.write("TIMEOUT\n")
    sys.stdout.flush()
s.close()
