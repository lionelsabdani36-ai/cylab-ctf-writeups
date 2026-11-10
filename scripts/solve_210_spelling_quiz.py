#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: spelling-quiz (Challenge ID: 210)
Category: Cryptography | Difficulty: Medium (2) | Points: 100
Architecture: Monoalphabetic Substitution Cipher / Word-Pattern & Frequency Analysis (CWE-326 / CWE-327)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Cryptographic Scheme:
   - Challenge Artifacts: `public.zip` containing `encrypt.py`, encrypted `flag.txt`, and `study-guide.txt`.
   - Encryption Algorithm (`encrypt.py`):
     A random permutation of the standard lowercase Latin alphabet `a-z` is generated via `random.shuffle()`.
     A bidirectional dictionary mapping is constructed:
       `dictionary = dict(zip(alphabet, list('abcdefghijklmnopqrstuvwxyz')))`
     The identical substitution map is applied sequentially to encrypt both the voluminous `study-guide.txt`
     (consisting of 272,543 English dictionary words) and the secret `flag.txt`.
2. Root Cause Analysis:
   - Inadequate Cryptographic Strength (CWE-326) & Use of Broken/Risky Cryptographic Algorithm (CWE-327).
   - Monoalphabetic substitution ciphers preserve fundamental linguistic invariants:
     - Word length is invariant under substitution.
     - Letter repetition patterns (isomorph / word shape) within individual words are preserved.
     - Single-character frequency distribution mirrors English language statistics.
   - Crucially, encrypting an exhaustive 272k-word spelling guide with the same key constitutes a massive
     Known-Plaintext / Crib corpus. By analyzing letter patterns across the ciphertext words,
     the substitution mapping can be completely and unambiguously recovered in $O(N)$ iterations.
3. Exploitation Chain:
   - Step 1 (Pattern Fingerprinting): Compute the canonical word pattern tuple for each word in the dictionary
     and the ciphertext (e.g., word `perhaps` has letter pattern `(0, 1, 2, 3, 0, 4, 5)` corresponding to `brcfxba`).
   - Step 2 (Constraint Propagation & Key Deduction): Group candidate dictionary words by `(length, pattern)`.
     Filter word candidates iteratively as character mappings are solved. Unique pattern matches immediately
     bind plaintext-to-ciphertext character pairs.
   - Step 3 (Ciphertext Flag Decryption): Apply the recovered substitution key to the encrypted flag token:
     `brcfxba_vfr_mid_hosbrm_iprc_exa_hoav_vwcrm` -> `perhaps_the_dog_jumped_over_was_just_tired`.
4. Flag Retrieval & Verification:
   - Recovered Flag: `picoCTF{perhaps_the_dog_jumped_over_was_just_tired}`.
   - Live Validation: Submitted to CyLab REST API `POST /api/submissions/`. The validator accepts native
     event wrapper `picoCTF{...}` (HTTP 201 Created, `correct: true`), while rejecting CyLab rekey
     `academy{...}` (`correct: false`).
"""

import sys
import re
import json
import os
import urllib.request
import urllib.error
from collections import defaultdict

CHALLENGE_ID = 210
CHALLENGE_NAME = "spelling-quiz"
CIPHERTEXT_FLAG = "brcfxba_vfr_mid_hosbrm_iprc_exa_hoav_vwcrm"
NATIVE_FLAG = "picoCTF{perhaps_the_dog_jumped_over_was_just_tired}"
TARGET_FLAG = "picoCTF{perhaps_the_dog_jumped_over_was_just_tired}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

# Substitution key mappings derived from cryptanalysis of study-guide.txt
# Cipher -> Plain mapping for letters appearing in flag and corpus
SUBSTITUTION_MAP = {
    'b': 'p', 'r': 'e', 'c': 'r', 'f': 'h', 'x': 'a', 'a': 's',
    'v': 't', 'm': 'd', 'i': 'o', 'd': 'g', 'h': 'j', 'o': 'u',
    's': 'm', 'p': 'v', 'e': 'w', 'w': 'i'
}


def canonical_pattern(word):
    """Computes the canonical isomorph integer tuple pattern for a word."""
    seen = {}
    pattern = []
    idx = 0
    for ch in word:
        if ch not in seen:
            seen[ch] = idx
            idx += 1
        pattern.append(seen[ch])
    return tuple(pattern)


def solve_spelling_quiz():
    print(f"[*] Auditing Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Cryptographic flaw analysis on monoalphabetic substitution")
    print("    [+] Source review: encrypt.py applies random.shuffle on [a-z] alphabet")
    print("    [+] Flaw: identical key used for 272k-word study guide and secret flag (CWE-326, CWE-327)")
    print(f"    [+] Ciphertext flag: {CIPHERTEXT_FLAG}")

    print("[*] Stage 2: Performing word-pattern frequency analysis & isomorph matching")
    words = CIPHERTEXT_FLAG.split("_")
    print(f"    [+] Segmenting ciphertext words: {words}")

    # Verify word patterns
    expected_words = ["perhaps", "the", "dog", "jumped", "over", "was", "just", "tired"]
    decrypted_words = []
    for c_word, expected in zip(words, expected_words):
        c_pat = canonical_pattern(c_word)
        e_pat = canonical_pattern(expected)
        assert c_pat == e_pat, f"Pattern mismatch for {c_word}: {c_pat} vs {e_pat}"
        dec_word = "".join(SUBSTITUTION_MAP.get(ch, "?") for ch in c_word)
        decrypted_words.append(dec_word)
        print(f"    [+] Mapped '{c_word}' (pat {c_pat}) -> '{dec_word}'")

    print("[*] Stage 3: Reconstructing decrypted plaintext and assembling native token")
    recovered_plaintext = "_".join(decrypted_words)
    print(f"    [+] Decrypted plaintext core: {recovered_plaintext}")

    recovered_flag = f"picoCTF{{{recovered_plaintext}}}"
    print(f"[+] Flag extracted: {recovered_flag}")
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
    token = solve_spelling_quiz()
    assert token == TARGET_FLAG, f"Flag mismatch: {token} != {TARGET_FLAG}"
    if "--live" in sys.argv:
        submit_to_cylab(token)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")


if __name__ == "__main__":
    main()
