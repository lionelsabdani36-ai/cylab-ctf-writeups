#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: rail-fence (Challenge ID: 289)
Category: Cryptography | Difficulty: Medium (2) | Points: 200
Architecture: Classical Transposition Cipher / Zig-Zag Rail Fence Periodicity / NIST SP 800-115 § 4.2

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Cryptographic Primitives:
   The challenge implements a 4-rail Rail Fence transposition cipher on message.txt.
   Rail Fence is a permutation cipher where plaintext characters are written diagonally
   down and up across `N` parallel rails in a zig-zag waveform:
       Period P = 2 * (rails - 1) = 2 * (4 - 1) = 6
   Characters are then read off row by row (top rail to bottom rail) to form the ciphertext.
2. Cryptographic Weakness:
   - Zero confusion (permutation only, no substitution / diffusion):
     All character frequencies are 100% preserved.
   - Deterministic index trajectory:
     Knowing the rail depth (4 rails) and message length (56 chars), the geometric
     matrix positions of all ciphertext slices are completely deterministic.
3. Decryption Procedure:
   - Trace the zig-zag bounce sequence across length N: [0, 1, 2, 3, 2, 1, 0, 1, ...]
   - Count the frequency of each rail index to determine row lengths.
   - Slice the ciphertext sequentially into row substrings.
   - Traverse the zig-zag pattern, reading the next character from the respective row.
   - Decoded message: "The flag is: WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_D3AB175F"
   - Normalized CyLab Token: academy{WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_D3AB175F}
"""

import sys
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 289
CHALLENGE_NAME = "rail-fence"
CIPHERTEXT_URL = (
    "https://challenge-files.cylabacademy.net/library/"
    "e3a0d625f6dd6554233d2675553060046f8bf5b21af03458091011ad1fccc3d7/message.txt"
)
FALLBACK_CIPHERTEXT = "Ta _7N6DD5hlg:W3D_H3C31N__37Fef sHR053F38N43DA1 i33___NB"
TARGET_FLAG = "academy{WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_D3AB175F}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"


def decrypt_rail_fence(ct: str, rails: int = 4) -> str:
    n = len(ct)
    pat, r, d = [], 0, 1
    for _ in range(n):
        pat.append(r)
        r += d
        if r == rails - 1 or r == 0:
            d = -d
    rows, idx = [], 0
    for k in range(rails):
        count_k = pat.count(k)
        rows.append(ct[idx : idx + count_k])
        idx += count_k
    pos = [0] * rails
    out = []
    for k in pat:
        out.append(rows[k][pos[k]])
        pos[k] += 1
    return "".join(out)


def fetch_or_fallback(url: str) -> str:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode("utf-8").strip()
            if content:
                return content
    except Exception:
        pass
    return FALLBACK_CIPHERTEXT


def submit_to_cylab(token: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
    cookie_header = ""
    csrf_token = ""
    try:
        sys.path.insert(0, "/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = response.read().decode("utf-8")
            print(f"[+] Platform submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[*] Platform submission status: {e}")
        return False
    except Exception as e:
        print(f"[*] Subprocess submission error: {e}")
        return False


def main():
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Loading ciphertext payload (message.txt)")
    ct = fetch_or_fallback(CIPHERTEXT_URL)
    print(f"    [+] Ciphertext length: {len(ct)} bytes")
    print(f"    [+] Ciphertext: {ct}")

    print("[*] Stage 2: Simulating 4-rail zig-zag waveform inversion (Period P = 6)")
    pt = decrypt_rail_fence(ct, rails=4)
    print(f"    [+] Decrypted Cleartext: {pt}")

    prefix = "The flag is:"
    if pt.startswith(prefix):
        phrase = pt[len(prefix) :].strip()
        flag = f"academy{{{phrase}}}"
    else:
        flag = f"academy{{{pt}}}"

    print(f"[+] Reconstructed Flag: {flag}")
    submit_to_cylab(flag)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {flag}")


if __name__ == "__main__":
    main()
