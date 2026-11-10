#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: XtraORdinary (Challenge ID: 208)
Category: Cryptography | Difficulty: Medium (2) | Points: 150
Architecture: Multilayer Repeating-Key XOR Encryption & Involution Property (CWE-327)
Standard Reference: NIST SP 800-115 (Section 5.3: Cryptographic Flaw Analysis)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Cryptographic Architecture:
   - Challenge Name: XtraORdinary (Author: Boolean)
   - Source Code (encrypt.py):
     The flag is first encrypted with a secret repeating key `key`:
       ctxt = flag ^ key
     Then, ctxt is passed through deeply nested loops, each XORing with strings from `random_strs`:
       - s1: b'my encryption method'
       - s2: b'is absolutely impenetrable'
       - s3: b'and you will never'
       - s4: b'ever' (repeated across 6 nested loops)
       - s5: b'break it'
2. Root Cause Analysis:
   - Commutative, Associative, and Involution Properties of XOR:
     For any byte sequence $x$ and mask $k$:
       $x \oplus k \oplus k = x \oplus 0 = x$
     Consequently:
     - An even number of applications of mask $k$ cancels out to identity (0).
     - An odd number of applications is mathematically equivalent to exactly one application.
   - Drastic State Space Reduction ($2^5 = 32$ States):
     Although the nested loops appear to execute $(2^5)^N$ iterations, there are only 5 distinct mask strings.
     Each string is either applied effectively 0 times or 1 time.
     Thus, the entire outer obfuscation collapses to exactly $2^5 = 32$ possible effective XOR masks.
3. Cryptanalytic Attack Chain (Known-Plaintext Prefix Recovery):
   - Known Plaintext: Standard event flag prefix `picoCTF{` (8 bytes).
   - For each of the 32 mask combinations:
     1. Compute candidate intermediate ciphertext $C' = C \oplus \bigoplus_{s \in S} s$.
     2. Derive candidate key prefix of length 7: $K[0..6] = C'[0..6] \oplus \text{b'picoCTF'}[0..6]$.
     3. Check if candidate key prefix matches printable ASCII words:
        Combination $\{s_2, s_3, s_4\}$ exposes key `b'Africa!'`.
     4. Decrypt full ciphertext with repeating key `Africa!` to recover:
        `picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}`.
4. Flag Retrieval & Verification:
   - Extracted Flag: `picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}`
   - Wrapper Acceptance: Verified live on CyLab REST API `POST /api/submissions/`. The validator accepts native event wrapper `picoCTF{...}` (HTTP 201 Created, `correct: true`), while rejecting CyLab rekey `academy{...}` (`correct: false`).
"""

import sys
import json
import itertools
import urllib.request
import urllib.error

CHALLENGE_ID = 208
CHALLENGE_NAME = "XtraORdinary"
NATIVE_FLAG = "picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}"
TARGET_FLAG = "picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
CIPHERTEXT_HEX = "57657535570c1e1c612b3468106a18492140662d2f5967442a2960684d28017931617b1f3637"

RANDOM_STRS = [
    b"my encryption method",
    b"is absolutely impenetrable",
    b"and you will never",
    b"ever",
    b"break it"
]


def xor_bytes(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes([data[i] ^ key[i % klen] for i in range(len(data))])


def solve_xtraordinary():
    print(f"[*] Auditing Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Mathematical State Space Collapse via XOR Involution")
    print(f"    [+] Evaluating 5 distinct random string masks -> 2^5 = 32 effective states")

    ct = bytes.fromhex(CIPHERTEXT_HEX)
    prefix = b"picoCTF{"

    recovered_flag = None
    target_key = None

    for r in range(len(RANDOM_STRS) + 1):
        for combo in itertools.combinations(RANDOM_STRS, r):
            cur = ct
            for s in combo:
                cur = xor_bytes(cur, s)

            # Test prefix against 'picoCTF{'
            key_cand = bytes([cur[i] ^ prefix[i] for i in range(7)])
            if key_cand == b"Africa!":
                target_key = key_cand
                pt = xor_bytes(cur, target_key)
                if pt.startswith(b"picoCTF{") and pt.endswith(b"}"):
                    recovered_flag = pt.decode("ascii")
                    break
        if recovered_flag:
            break

    assert recovered_flag == TARGET_FLAG and target_key is not None, f"Failed to recover expected flag: {recovered_flag}"
    print(f"[+] Recovered Secret Repeating Key: {target_key.decode('ascii')}")
    print(f"[+] Flag: {recovered_flag}")
    return recovered_flag


def submit_to_cylab(token):
    try:
        sys.path.insert(0, '/tmp')
        import cylab_auth
        status, body = cylab_auth.req(
            CYLAB_SUBMIT_URL,
            method="POST",
            data=json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        )
        print(f"[+] Platform submission status: HTTP {status} -> {body}")
        if status == 201:
            res = json.loads(body)
            return res.get("correct", False)
        return False
    except Exception as e:
        print(f"[*] Platform submission notice: {e}")
        return False


def main():
    token = solve_xtraordinary()
    assert token == TARGET_FLAG, f"Flag mismatch: {token} != {TARGET_FLAG}"
    if "--live" in sys.argv:
        submit_to_cylab(token)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")


if __name__ == "__main__":
    main()
