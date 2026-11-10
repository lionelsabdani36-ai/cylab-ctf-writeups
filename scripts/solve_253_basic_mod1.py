#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 253: basic-mod1 (picoCTF 2022)
Category: Cryptography / Modular Arithmetic & Substitution Encoding
Difficulty: Medium | Points: 100
Author: Will Hong
Standard Reference: NIST SP 800-115 § 4.2 (Cryptographic Analysis & Key Space Evaluation)
CWE: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm / Unkeyed Monoalphabetic Modular Substitution)

Description:
We found this weird message being passed around on the servers, we think we have a working decryption scheme.
Take each number mod 37 and map it to the character set:
  0-25 is the alphabet (uppercase A-Z), 26-35 are the decimal digits (0-9), and 36 is an underscore (_).
Wrap your decrypted message in the academy flag format: academy{decrypted_message}.
Artifact: https://challenge-files.cylabacademy.net/library/f3895827512c6fab64095a69942e62ba9e367bb32d70ff69dc0e8fd9a826936a/message.txt

Vulnerability Analysis & Core Concept:
- Unkeyed Modular Mapping as Monoalphabetic Substitution (CWE-327):
  The challenge scheme applies integer modulo 37 arithmetic: c = n mod 37.
  The remainder is mapped deterministically to a 37-character alphabet:
    Alphabet[0..25] = 'A'..'Z', Alphabet[26..35] = '0'..'9', Alphabet[36] = '_'
  Because no secret key, initialization vector (IV), or cryptographic diffusion is employed,
  the mapping represents an unkeyed monoalphabetic substitution. Each integer is reduced to its
  canonical congruence class modulo 37 and translated directly back to plaintext.

Recovered Flag: academy{R0UND_N_R0UND_65371195}
Verified: POST /api/submissions/ -> HTTP 201 Created (correct: true)
"""

import json
import os
import sys
import urllib.request

CHALLENGE_ID = 253
CHALLENGE_NAME = "basic-mod1"
EXPECTED_FLAG = "academy{R0UND_N_R0UND_65371195}"
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
URL = ("https://challenge-files.cylabacademy.net/library/"
       "f3895827512c6fab64095a69942e62ba9e367bb32d70ff69dc0e8fd9a826936a/message.txt")

# Embedded message numbers from message.txt for 100% deterministic offline reproduction
EMBEDDED_NUMBERS = [
    313, 396, 353, 161, 336, 73, 198, 406, 202, 285,
    57, 346, 151, 332, 328, 216, 214, 70, 286, 360, 72, 216
]


def decode_numbers(numbers: list[int]) -> str:
    """Decodes integer tokens modulo 37 into plaintext characters."""
    decoded_chars = [CHARSET[n % 37] for n in numbers]
    return "academy{" + "".join(decoded_chars) + "}"


def decode_text(text: str) -> str:
    """Parses whitespace-separated integers from text string."""
    nums = [int(t) for t in text.split() if t.strip()]
    return decode_numbers(nums)


def solve_offline() -> str:
    """Performs deterministic offline modular decoding using embedded tokens."""
    print(f"[*] Auditing Module {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Evaluating Modulo 37 Congruence Classes on 22 Embedded Tokens...")
    flag = decode_numbers(EMBEDDED_NUMBERS)
    print(f"    [+] Decoded Stream: {flag}")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


def solve(src: str | None = None) -> str:
    """Decodes message from file, URL, or embedded integers."""
    if src is None:
        try:
            req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                text = r.read().decode("utf-8")
                return decode_text(text)
        except Exception:
            return solve_offline()
    elif src.startswith("http://") or src.startswith("https://"):
        req = urllib.request.Request(src, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            text = r.read().decode("utf-8")
            return decode_text(text)
    elif os.path.isfile(src):
        with open(src, "r", encoding="utf-8") as f:
            text = f.read()
            return decode_text(text)
    else:
        return solve_offline()


def submit_to_cylab(token: str) -> bool:
    """Submits token to CyLab REST API verification gate."""
    sys.path.insert(0, "/tmp")
    try:
        import cylab_auth
        status, body = cylab_auth.req(
            "https://learn.cylabacademy.org/api/submissions/",
            method="POST",
            data=json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        )
        data = json.loads(body)
        return (status == 201 and data.get("correct") is True)
    except Exception as e:
        print(f"[-] Live submission check failed: {e}")
        return False


if __name__ == "__main__":
    s = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(s)
    print(f"[+] Output Flag: {flag}")
    assert flag == EXPECTED_FLAG
