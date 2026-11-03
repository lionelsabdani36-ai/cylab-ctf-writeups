#!/usr/bin/env python3
"""
Solves CyLab Security Academy Challenge 73: miniRSA
Category: Cryptography
Platform: picoCTF 2019
Author: speeeday/Danny
Points: 300

Vulnerability Analysis:
- Architecture: Textbook RSA encryption with small public exponent e = 3.
- Cryptographic Flaw: Low Public Exponent Attack (Coppersmith / Direct Root Extraction).
  When public exponent e is small (here e = 3) and no proper randomized padding (like OAEP)
  is applied, the cleartext message m satisfies:
    c = m^e (mod N)
  If the message m is small enough such that m^e < N, the modular reduction mod N never occurs.
  Therefore:
    c = m^3 (over integers)
    m = floor(c^(1/3))
  Even if m^3 slightly exceeds N (i.e. c = m^3 mod N, where c = m^3 - k*N), for small k:
    m = floor((c + k*N)^(1/3))
  In this challenge, m^3 < N (k = 0), allowing direct integer cube root recovery.

Flag: academy{n33d_a_lArg3r_e_e2b360ae}
Verified: POST /api/submissions/ -> correct: true, HTTP 201 Created
"""

import sys
import urllib.request

CIPHERTEXT_URL = "https://challenge-files.cylabacademy.net/library/9c6677c26fc49e4a388d281e4c5197ebfa1151f65d53f9db8753ff455da9bf31/ciphertext"

def iroot(n: int, k: int = 3) -> int:
    """Integer k-th root using binary search."""
    if n < 0:
        raise ValueError("Cannot take real root of negative integer")
    if n == 0:
        return 0
    lo = 1
    hi = 1 << ((n.bit_length() + k - 1) // k)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** k < n:
            lo = mid + 1
        else:
            hi = mid
    return lo if lo ** k == n else -1

def solve_from_data(data: str) -> str:
    lines = [line.strip() for line in data.splitlines() if line.strip()]
    vals = {}
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            key = k.strip()
            val = int(v.strip())
            if "ciphertext" in key.lower() or "(c)" in key.lower():
                vals["c"] = val
            elif key.lower() == "n":
                vals["N"] = val
            elif key.lower() == "e":
                vals["e"] = val

    N = vals["N"]
    e = vals["e"]
    c = vals["c"]

    # Search for k such that c + k*N is a perfect e-th power
    for k in range(1000):
        val = c + k * N
        m = iroot(val, e)
        if m != -1:
            byte_len = (m.bit_length() + 7) // 8
            flag_bytes = m.to_bytes(byte_len, "big")
            try:
                flag = flag_bytes.decode("ascii")
                if "academy{" in flag:
                    return flag
            except UnicodeDecodeError:
                pass
    raise RuntimeError("Failed to recover plaintext flag")

def main():
    try:
        req = urllib.request.Request(
            CIPHERTEXT_URL,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req) as resp:
            data = resp.read().decode("utf-8")
    except Exception as e:
        print(f"Error fetching remote ciphertext: {e}", file=sys.stderr)
        # Fallback embedded parameters from challenge
        data = """
N: 29331922499794985782735976045591164936683059380558950386560160105740343201513369939006307531165922708949619162698623675349030430859547825708994708321803705309459438099340427770580064400911431856656901982789948285309956111848686906152664473350940486507451771223435835260168971210087470894448460745593956840586530527915802541450092946574694809584880896601317519794442862977471129319781313161842056501715040555964011899589002863730868679527184420789010551475067862907739054966183120621407246398518098981106431219207697870293412176440482900183550467375190239898455201170831410460483829448603477361305838743852756938687673
e: 3
ciphertext (c): 1434021793376841821609560098489408479192223685550855374860108343524329971439527270014700659467728993670678746820157646645310848073373778698452694869112226384087192892309346330774874577850541639346711433351787695134266969185864868945032293
        """
    flag = solve_from_data(data)
    print(f"[+] Flag: {flag}")

if __name__ == "__main__":
    main()
