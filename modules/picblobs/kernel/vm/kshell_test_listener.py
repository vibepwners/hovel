#!/usr/bin/env python3
"""Test listener for kshell.ko — run inside the VM."""

import socket
import sys
import time

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 4444))
srv.listen(1)
srv.settimeout(30)

try:
    conn, addr = srv.accept()
    sys.stdout.write("CONNECTED\n")
    sys.stdout.flush()
    conn.settimeout(5)

    # Read banner
    time.sleep(2)
    try:
        banner = conn.recv(4096)
        sys.stdout.write("BANNER: " + repr(banner[:300]) + "\n")
        sys.stdout.flush()
    except TimeoutError:
        sys.stdout.write("BANNER: timeout\n")
        sys.stdout.flush()

    # Send 'id' command
    conn.sendall(b"id\n")
    time.sleep(5)
    try:
        resp = conn.recv(65536)
        sys.stdout.write("RESP_ID: " + repr(resp[:500]) + "\n")
        sys.stdout.flush()
    except TimeoutError:
        sys.stdout.write("RESP_ID: timeout\n")
        sys.stdout.flush()

    # Send 'uname -a'
    conn.sendall(b"uname -a\n")
    time.sleep(5)
    try:
        resp = conn.recv(65536)
        sys.stdout.write("RESP_UNAME: " + repr(resp[:500]) + "\n")
        sys.stdout.flush()
    except TimeoutError:
        sys.stdout.write("RESP_UNAME: timeout\n")
        sys.stdout.flush()

    conn.sendall(b"exit\n")
    time.sleep(1)
    conn.close()
    sys.stdout.write("DONE\n")

except TimeoutError:
    sys.stdout.write("ERROR: no connection within 30s\n")
except Exception as e:
    sys.stdout.write("ERROR: " + str(e) + "\n")
finally:
    srv.close()
