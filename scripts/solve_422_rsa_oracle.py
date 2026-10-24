#!/usr/bin/env python3
"""
Solver for Challenge 422: rsa_oracle (Module 140, LP 17)
CyLab Security Academy / picoCTF 2024
Vulnerability: RSA Chosen Ciphertext Attack (CCA) via homomorphic multiplication property
"""
import socket
import subprocess
import sys
import time

def solve(host, port, password_enc_path="password.enc", secret_enc_path="secret.enc"):
    with open(password_enc_path, "r") as f:
        c_target = int(f.read().strip())

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, int(port)))

    def recv_until(delim):
        buf = b""
        while delim not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf.decode('utf-8', errors='ignore')

    # Read banner
    recv_until("decrypt.\n")

    # Step 1: Encrypt chosen multiplier character 'a' (ASCII 97)
    s.sendall(b"E\n")
    recv_until("keysize): ")
    s.sendall(b"a\n")
    out = recv_until("decrypt.\n")
    # Parse ciphertext (m ^ e mod n)
    c1 = None
    for line in out.splitlines():
        if "mod n)" in line:
            c1 = int(line.split("mod n)")[1].strip())
            break
        elif any(c.isdigit() for c in line) and len(line.strip()) > 30:
            parts = [p for p in line.split() if p.isdigit()]
            if parts:
                c1 = int(parts[-1])
                break

    assert c1 is not None, f"Failed to parse ciphertext c1 from: {out}"

    # Step 2: Compute homomorphic ciphertext c2 = c_target * c1
    c2 = c_target * c1

    # Step 3: Decrypt c2 via oracle
    s.sendall(b"D\n")
    recv_until("decrypt: ")
    s.sendall(f"{c2}\n".encode())
    out = recv_until("decrypt.\n")

    # Parse decrypted cleartext as hex
    m2_hex = None
    for line in out.splitlines():
        if "mod n):" in line or "cleartext" in line.lower():
            parts = line.split(":")[-1].strip().split()
            m2_hex = parts[0]
            break

    if not m2_hex:
        # Fallback to search hex tokens
        for token in out.split():
            try:
                int(token, 16)
                if len(token) > 10:
                    m2_hex = token
                    break
            except ValueError:
                pass

    assert m2_hex is not None, f"Failed to parse decrypted cleartext from: {out}"

    m2 = int(m2_hex, 16)
    m_password = m2 // ord('a')
    password_bytes = m_password.to_bytes((m_password.bit_length() + 7) // 8, 'big').lstrip(b'\x00')
    password = password_bytes.decode('utf-8', errors='ignore')
    print("Recovered Password:", password)

    s.close()

    # Step 4: Decrypt secret.enc using openssl aes-256-cbc
    cmd = ["openssl", "enc", "-aes-256-cbc", "-d", "-in", secret_enc_path, "-pass", f"pass:{password}"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    flag = res.stdout.strip()
    print("Flag:", flag)
    return flag

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <port> [password_enc] [secret_enc]")
        sys.exit(1)
    solve(sys.argv[1], sys.argv[2])
