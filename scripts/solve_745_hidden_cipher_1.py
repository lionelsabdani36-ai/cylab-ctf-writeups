#!/usr/bin/env python3
"""Solver for Challenge 745 Hidden Cipher 1 (picoCTF 2026, Reverse Engineering).

Binary ships UPX-packed; unpack with `upx -d` (hint 1). `get_secret`
writes the repeating key "S3Cr3t" (6 bytes) into .bss. Main loop encrypts
each flag byte as: enc[i] = flag[i] ^ key[(6*i - 6*(i//6)) % 6]  (i.e. the
imul 0x2aaaaaab / shr 0x20 sequence is unsigned i//6, then i - 6*(i//6)
gives i % 6). Output is lowercase hex.

Lab serves the per-instance ciphertext over netcat (on-demand instance).
Decryption is symmetric: flag[i] = enc[i] ^ key[i % 6].

Usage: solve_745_hidden_cipher_1.py [host] [port]
Verified: academy{xor_unpack_4nalys1s_f3d3a874} (POST /api/submissions/ -> correct:true)
"""
import socket
import sys

HOST = "chatelaine.cylabacademy.net"
PORT = 22038
KEY = b"S3Cr3t"
EXPECTED = "academy{xor_unpack_4nalys1s_f3d3a874}"


def fetch_ciphertext(host: str = HOST, port: int = PORT, timeout: int = 20) -> str:
    s = socket.create_connection((host, int(port)), timeout=timeout)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 4096:
                break
    finally:
        s.close()
    text = data.decode(errors="replace")
    hexline = [ln.strip() for ln in text.splitlines() if ln.strip().replace("0123456789abcdef", "").strip("0123456789abcdef") == "" and len(ln.strip()) >= 16]
    if not hexline:
        raise ValueError("no ciphertext line in lab output: %r" % text[:200])
    return hexline[0]


def decrypt(ct_hex: str, key: bytes = KEY) -> str:
    ct = bytes.fromhex(ct_hex.strip())
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(ct)).decode()


def solve(host: str = HOST, port: int = PORT) -> str:
    ct_hex = fetch_ciphertext(host, port)
    print("ciphertext:", ct_hex)
    flag = decrypt(ct_hex)
    print("flag:", flag)
    assert flag == EXPECTED, flag
    return flag


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(solve(host, port))
