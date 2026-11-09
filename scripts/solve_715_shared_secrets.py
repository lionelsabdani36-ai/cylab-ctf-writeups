#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Shared Secrets (Challenge ID: 715)
Category: Cryptography / Diffie-Hellman Key Agreement & Sensitive Exponent Leakage
Difficulty: Easy (1) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
RFC 2631 (Diffie-Hellman Key Agreement Method), RFC 3526 (Modular Exponential MODP Groups),
& CWE-312 / CWE-200 (Cleartext Storage and Exposure of Sensitive Information - Leaked Ephemeral Exponent).

Vulnerability & Technical Summary:
1. Architecture & Protocol Mechanics:
   - Challenge simulates a Diffie-Hellman (DH) key exchange over a finite cyclic group Z_p^*.
   - Public parameters: Prime modulus p (768 bits) and generator g = 2.
   - Party A (Server) generates private exponent a and transmits public key A = g^a mod p.
   - Party B (Client) generates private exponent b and transmits public key B = g^b mod p.
   - The agreed shared secret is K = g^(ab) mod p.
2. Sensitive Private Exponent Exposure (CWE-312 / CWE-200):
   - In standard DH, computing K from public values (p, g, A, B) requires solving the Computational Diffie-Hellman
     (CDH) or Discrete Logarithm Problem (DLP), which is computationally infeasible for sufficiently large primes.
   - However, in `transcript.txt`, Party B mistakenly leaks its private exponent `b`.
   - Any observer possessing public key A and private exponent b can directly evaluate:
     K = pow(A, b, p)
     completely bypassing DLP without needing server private key `a`.
3. Inadequate Key Derivation (CWE-326):
   - Rather than utilizing a standardized Key Derivation Function (HKDF / PBKDF2), the script derives
     the symmetric encryption key by simple modulo reduction:
     key = K % 256
   - This single-byte key (8 bits of entropy) is XORed against the ciphertext bytes.
   - Decryption yields: `academy{dh_s3cr3t_e3954beb}`.
   - REST API Submission: POST /api/submissions/ -> HTTP 201 (correct: true).
"""

import os
import sys
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 715
CHALLENGE_NAME = "Shared Secrets"
VERIFIED_FLAG = "academy{dh_s3cr3t_e3954beb}"
COMMUNITY_FLAG = "CTF{dh_s3cr3t_e3954beb}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

# Default cryptographic parameters from challenge transcript
DEFAULT_P = int(
    "2188545828481232917915233525806579818209760678972220490921380750542193455665345717562182558864409541451041964360901352616297280654258287473010375935406137903689564954762347824228761657501247248979653142698163854882116855521952627898416433209318642163322021284188040749653581645061299781147685165607754045402815547537"
)
DEFAULT_A = int(
    "529022054504968019469968111961692103333962097204384321062327406113469798583084528471911087369430603184315616289885944538403549216006196112599856159910375335838601931262259012757936708816266131815368447196183194865289491972488369456495842428832190461512811822688595599282473173695956797450916384282506132120013828366"
)
DEFAULT_B = int(
    "806108241018714272971792803761488787583500782708354296181179175643414634637904065955198182937625129233790050616136051643206357851994861572647233251265904450054206496643678855386739080010799844605476667118318730605723614207809884834764849344555331442139243115610235608110485560140584263429781350962431123512110941522"
)
DEFAULT_ENC_HEX = "b7b5b7b2b3bbafadb2be89a5e5b5a4e5a289b3e5efe3e2b4b3b4ab"


class SharedSecretsSimulator:
    """
    Simulates Diffie-Hellman shared key reconstruction and modular key derivation.
    """
    def __init__(self, p: int = DEFAULT_P, a_pub: int = DEFAULT_A, b_priv: int = DEFAULT_B, enc_hex: str = DEFAULT_ENC_HEX):
        self.p = p
        self.a_pub = a_pub
        self.b_priv = b_priv
        self.enc_bytes = bytes.fromhex(enc_hex.strip())

    def decrypt(self) -> str:
        # Compute Diffie-Hellman shared secret K = A^b mod p
        shared_secret = pow(self.a_pub, self.b_priv, self.p)
        key_byte = shared_secret % 256
        recovered = bytes([x ^ key_byte for x in self.enc_bytes])
        return recovered.decode("utf-8", errors="replace")


def parse_transcript(transcript_path: str) -> SharedSecretsSimulator:
    p = DEFAULT_P
    a_pub = DEFAULT_A
    b_priv = DEFAULT_B
    enc_hex = DEFAULT_ENC_HEX

    with open(transcript_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("p ="):
                p = int(line.split("=")[1].strip())
            elif line.startswith("A ="):
                a_pub = int(line.split("=")[1].strip())
            elif line.startswith("b ="):
                b_priv = int(line.split("=")[1].strip())
            elif line.startswith("enc =") or line.startswith("ciphertext ="):
                val = line.split("=")[1].strip().strip("'\"")
                enc_hex = val

    return SharedSecretsSimulator(p, a_pub, b_priv, enc_hex)


def solve_from_file(transcript_path: str) -> str:
    print(f"[*] Parsing transcript from: {transcript_path}")
    sim = parse_transcript(transcript_path)
    flag = sim.decrypt()
    print(f"[+] Decrypted flag: {flag}")
    return flag


def verify_local_simulation() -> str:
    sim = SharedSecretsSimulator()
    flag = sim.decrypt()
    assert flag == VERIFIED_FLAG, f"Decryption mismatch: {flag} vs {VERIFIED_FLAG}"
    print(f"[+] Local simulation and parameter test PASSED: {flag}")
    return flag


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

    if not cookie_header or not csrf_token:
        print("[!] Autentikasi sesi CyLab tidak ditemukan di /tmp/cylab_auth.py.")
        return False

    req = urllib.request.Request(
        CYLAB_SUBMIT_URL,
        data=payload,
        method="POST",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Cookie": cookie_header,
            "X-CSRFToken": csrf_token,
            "Content-Type": "application/json",
            "Referer": "https://learn.cylabacademy.org/challenges"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            status = data.get("status") or (data.get("correct") is True)
            print(f"[+] Status submisi CyLab (HTTP {resp.status}): {data}")
            return bool(status)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[-] Submisi gagal (HTTP {e.code}): {body}")
        return False


def main():
    print(f"=== [CyLab Academy] Solusi Modul #{CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    default_transcript = "transcript.txt"
    flag = None

    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        path = sys.argv[1]
        if os.path.exists(path):
            flag = solve_from_file(path)
        else:
            print(f"[!] Berkas {path} tidak ditemukan, fallback ke simulasi lokal.")
            flag = verify_local_simulation()
    elif os.path.exists(default_transcript):
        flag = solve_from_file(default_transcript)
    else:
        flag = verify_local_simulation()

    print(f"[+] Flag berhasil direkonstruksi: {flag}")

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
