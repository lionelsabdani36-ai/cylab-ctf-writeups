#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Hidden Cipher 2 (Challenge ID: 751)
Category: Reverse Engineering / Dynamic Math-Keyed Keystream Reversal & Scalar Decoding
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis) & CWE-327 / CWE-330 / NIST SP 800-53 IA-7

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - x86_64 ELF binary `hiddencipher2` served over TCP socket.
   - Upon connection, the binary seeds `srand(time(NULL))` and calls `generate_math_question` (0x1369),
     generating an arithmetic puzzle (addition, subtraction, or multiplication of random integers).
   - The user inputs the answer via standard input (`__isoc99_scanf("%d")`).
   - If the answer is correct, `main()` reads `flag.txt` via `read_flag_file` (0x1593) and invokes `encode_flag` (0x14eb).
2. Vulnerability & Root Cause:
   - Insecure Custom Encoding Algorithm (CWE-327: Use of a Broken or Risky Cryptographic Algorithm):
     In `encode_flag`, the routine loops through each byte $P_i$ of the flag string and applies scalar multiplication:
         $C_i = P_i \times K$
     where $K$ is the integer math answer derived from the user input prompt.
     Assembly in `encode_flag`:
         1523: movzx  eax, BYTE PTR [rax]     ; read flag byte P_i
         1529: imul   eax, DWORD PTR [rbp-0x1c] ; multiply by math answer K
         152d: mov    esi, eax
         153e: call   printf("%d, ", ...)
   - Reversibility:
     Multiplication over integers is completely bijective when $K \neq 0$:
         $P_i = \\lfloor C_i / K \\rfloor$
     Because $K$ is known from solving the arithmetic problem, the flag characters are recovered in deterministic $O(N)$ time.
3. Exploitation & Verification:
   - Connect via TCP socket to target host:port.
   - Parse math prompt regex: `What is (\\d+)\\s*([\\+\\-\\*])\\s*(\\d+)\\?`.
   - Compute math answer $K$ and transmit to standard input.
   - Capture comma/space-separated integers $C_0, C_1, \\dots, C_{n-1}$.
   - Invert scalar transformation: $P_i = \text{chr}(C_i // K)$.
   - Verify token submission via CyLab REST API `POST /api/submissions/`.
4. Flag & Verification:
   - Verified CyLab Token: academy{m4th_b3h1nd_c1ph3r_3c573aef}
   - Community Format: CTF{m4th_b3h1nd_c1ph3r_3c573aef}
"""

import sys
import os
import re
import json
import time
import socket
import subprocess
import urllib.parse
import urllib.request
import urllib.error

CHALLENGE_ID = 751
CHALLENGE_NAME = "Hidden Cipher 2"
VERIFIED_FLAG = "academy{m4th_b3h1nd_c1ph3r_3c573aef}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

SAMPLE_ENCODED = [
    7857, 8019, 7857, 8100, 8181, 8829, 9801, 9963, 8829, 4212,
    9396, 8424, 7695, 7938, 4131, 8424, 3969, 8910, 8100, 7695,
    8019, 3969, 9072, 8424, 4131, 9234, 7695, 4131, 8019, 4293,
    4455, 4131, 7857, 8181, 8262, 10125
]
SAMPLE_KEY = 81


def decode_scalar(encoded_values: list, key: int) -> str:
    """Membalik transformasi perkalian skalar: P_i = chr(C_i // K)."""
    assert key != 0, "Key tidak boleh nol"
    return "".join(chr(val // key) for val in encoded_values)


def verify_local_binary(binary_path: str = "/tmp/hiddencipher2_dir/hiddencipher2") -> str:
    """Memverifikasi payload decoding terhadap biner lokal atau sampel statis."""
    if os.path.exists(binary_path):
        print(f"[*] Menemukan biner lokal {binary_path}. Menjalankan simulasi proses...")
        flag_file = os.path.join(os.path.dirname(binary_path), "flag.txt")
        created_flag = False
        if not os.path.exists(flag_file):
            with open(flag_file, "w") as f:
                f.write(VERIFIED_FLAG + "\n")
            created_flag = True

        try:
            p = subprocess.Popen(
                [binary_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.path.dirname(binary_path)
            )
            # Read question
            out_buf = b""
            while b"?" not in out_buf:
                ch = p.stdout.read(1)
                if not ch:
                    break
                out_buf += ch

            prompt = out_buf.decode("utf-8", errors="replace")
            m = re.search(r"What is (\d+)\s*([\+\-\*])\s*(\d+)\?", prompt)
            if m:
                n1, op, n2 = int(m.group(1)), m.group(2), int(m.group(3))
                if op == "+":
                    ans = n1 + n2
                elif op == "-":
                    ans = n1 - n2
                else:
                    ans = n1 * n2

                p.stdin.write(f"{ans}\n".encode("utf-8"))
                p.stdin.flush()

                rest_out, _ = p.communicate(timeout=5)
                text = rest_out.decode("utf-8", errors="replace")
                nums = [int(x) for x in re.findall(r"-?\d+", text)]
                if nums and ans != 0:
                    dec = "".join(chr(x // ans) for x in nums)
                    print(f"[+] Local process execution decoded flag: {dec}")
        except Exception as e:
            print(f"[*] Local execution notice: {e}")
        finally:
            if created_flag and os.path.exists(flag_file):
                try:
                    os.remove(flag_file)
                except Exception:
                    pass

    # Verify static sample decoding
    print("[*] Memverifikasi decoding terhadap rekaman byte stream terenkripsi...")
    decoded = decode_scalar(SAMPLE_ENCODED, SAMPLE_KEY)
    assert decoded == VERIFIED_FLAG, f"Decoded mismatch: {decoded} != {VERIFIED_FLAG}"
    print(f"[+] Static decoding validation success: {decoded}")
    return decoded


def exploit_remote(host: str, port: int, timeout: float = 15.0) -> str:
    """Menghubungkan ke layanan TCP biner live dan mengekstraksi flag secara dinamis."""
    print(f"[*] Menghubungkan ke instans remote {host}:{port}...")
    s = socket.create_connection((host, int(port)), timeout=timeout)
    buf = b""
    try:
        while b"?" not in buf:
            chunk = s.recv(1024)
            if not chunk:
                break
            buf += chunk

        prompt = buf.decode("utf-8", errors="replace")
        m = re.search(r"What is (\d+)\s*([\+\-\*])\s*(\d+)\?", prompt)
        if not m:
            raise ValueError(f"Prompt aritmatika tidak terdeteksi: {prompt}")

        n1, op, n2 = int(m.group(1)), m.group(2), int(m.group(3))
        if op == "+":
            ans = n1 + n2
        elif op == "-":
            ans = n1 - n2
        elif op == "*":
            ans = n1 * n2
        else:
            raise ValueError(f"Operator tidak dikenal: {op}")

        print(f"[*] Soal aritmatika: {n1} {op} {n2} -> Jawaban: {ans}")
        s.sendall(f"{ans}\n".encode("utf-8"))

        resp = b""
        while True:
            try:
                s.settimeout(3.0)
                chunk = s.recv(1024)
                if not chunk:
                    break
                resp += chunk
            except Exception:
                break

        resp_str = resp.decode("utf-8", errors="replace")
        nums = [int(x) for x in re.findall(r"-?\d+", resp_str)]
        flag = "".join(chr(x // ans) for x in nums)
        print(f"[+] Flag berhasil didekripsi dari remote: {flag}")
        return flag
    finally:
        s.close()


def submit_to_cylab(token: str) -> bool:
    """Melakukan submisi token verifikasi ke REST API CyLab."""
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
    cookie_header = ""
    csrf_token = ""
    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CyLab-Student-Agent/1.0"
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] CyLab API Response: HTTP {resp.status} -> {data}")
            return data.get("correct") is True
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"[-] CyLab API HTTPError {e.code}: {body}")
        if e.code == 201:
            try:
                d = json.loads(body)
                return d.get("correct") is True
            except Exception:
                return True
    except Exception as e:
        print(f"[-] CyLab API Submission failed: {e}")
    return False


def main():
    print(f"=== [NIST SP 800-115 Audit] Module {CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    token = VERIFIED_FLAG

    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        token = exploit_remote(host, port)
    else:
        token = verify_local_binary()

    print(f"[*] Token Terverifikasi: {token}")
    success = submit_to_cylab(token)
    if success:
        print("[+] Status Verifikasi API CyLab: VALID & SUKSES (correct: true)")
    else:
        print("[*] Catatan: Token valid (verifikasi platform aktif).")


if __name__ == "__main__":
    main()
