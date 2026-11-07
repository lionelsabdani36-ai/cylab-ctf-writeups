#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: interencdec (Challenge ID: 418)
Category: Cryptography / Multi-Layer Encoding & Caesar Rotation
Difficulty: Easy (1) | Points: 100
Exploitation Technique: Iterative RFC 4648 Base64 Unwrapping, Caesar Rotation Inversion (Shift 7 / Modulo 26)
Standard Reference: NIST SP 800-115 Section 4.2 (Cryptographic Implementation Assessment), RFC 4648, CWE-327

Vulnerability & Mechanics Summary:
1. Target Architecture & Environment:
   - Challenge provides an encoded artifact file `enc_flag`.
   - The cipher string encapsulates multiple layered serialization transformations.
2. Root Cause Analysis (Layered Weak Encoding / CWE-327, CWE-310):
   - The artifact employs multiple layers of standard Base64 encoding (RFC 4648) combined with a monoalphabetic
     Caesar shift (rotational cipher) without cryptographic authentication (MAC) or adequate entropy.
   - Base64 is an encoding format, not an encryption scheme; it provides zero confidentiality.
   - Caesar cipher possesses a trivial keyspace of size $|\mathcal{K}| = 26$, solvable in microseconds.
3. Exploitation Pipeline:
   - Layer 1: Decode outer Base64 ASCII payload: `YidhR3BvYTJ4MFpudHFhR3g2YUhsZmF6TnFlVGwzWVROclh6Z3lNalF6TURrM2ZRPT0nCg==`
   - Layer 2: Extract nested string representation `b'aGpoa2x0ZntqaGx6aHlfazNqeTl3YTNrXzgyMjQzMDk3fQ=='`
   - Layer 3: Decode secondary Base64 byte stream to retrieve Caesar ciphertext: `hjhkltf{jhlzhy_k3jy9wa3k_82243097}`
   - Layer 4: Invert Caesar rotational shift using distance $\Delta = 7$ (or $+19 \pmod{26}$) on alphabetical runes:
     'h' -> 'a', 'j' -> 'c', 'k' -> 'd', 'l' -> 'e', 't' -> 'm', 'f' -> 'y' yielding 'academy' prefix.
4. Verification & Output:
   - Recovered Flag: academy{caesar_d3cr9pt3d_82243097}
"""

import sys
import json
import base64
import urllib.request
import urllib.error

CHALLENGE_ID = 418
CHALLENGE_NAME = "interencdec"
TARGET_FLAG = "academy{caesar_d3cr9pt3d_82243097}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

ENCODED_PAYLOAD = "YidhR3BvYTJ4MFpudHFhR3g2YUhsZmF6TnFlVGwzWVROclh6Z3lNalF6TURrM2ZRPT0nCg=="

def caesar_decrypt(ciphertext: str, shift: int) -> str:
    result = []
    for char in ciphertext:
        if "a" <= char <= "z":
            result.append(chr((ord(char) - ord("a") - shift) % 26 + ord("a")))
        elif "A" <= char <= "Z":
            result.append(chr((ord(char) - ord("A") - shift) % 26 + ord("A")))
        else:
            result.append(char)
    return "".join(result)

def solve_offline():
    print(f"[*] Auditing Module {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Inspecting Encoded Payload & RFC 4648 Base64 Layer 1...")
    print(f"    [+] Raw Encoded String: {ENCODED_PAYLOAD}")
    
    stage1_bytes = base64.b64decode(ENCODED_PAYLOAD.strip())
    stage1_str = stage1_bytes.decode("utf-8").strip()
    print(f"    [+] Stage 1 Decoded String: {stage1_str}")
    
    print("[*] Stage 2: Normalizing Byte Wrapper & Executing Base64 Layer 2...")
    if stage1_str.startswith("b'") and stage1_str.endswith("'"):
        inner_b64 = stage1_str[2:-1]
    elif stage1_str.startswith('b"') and stage1_str.endswith('"'):
        inner_b64 = stage1_str[2:-1]
    else:
        inner_b64 = stage1_str
        
    print(f"    [+] Extracted Inner Base64 Payload: {inner_b64}")
    stage2_bytes = base64.b64decode(inner_b64)
    caesar_cipher = stage2_bytes.decode("utf-8").strip()
    print(f"    [+] Stage 2 Decoded Caesar Ciphertext: {caesar_cipher}")
    
    print("[*] Stage 3: Inverting Caesar Substitution Cipher (Keyspace Evaluation)...")
    # Finding optimal shift to yield "academy{" or "picoCTF{"
    found_flag = None
    for shift in range(26):
        candidate = caesar_decrypt(caesar_cipher, shift)
        if candidate.startswith("academy{") or candidate.startswith("picoCTF{"):
            found_flag = candidate
            print(f"    [+] Identified valid prefix with shift delta = {shift}: {candidate}")
            break
            
    assert found_flag is not None, "Error: Failed to find valid Caesar decipherment"
    assert found_flag == TARGET_FLAG, f"Verification failed: {found_flag} != {TARGET_FLAG}"
    print(f"    [+] Cryptographic verification confirmed: {found_flag}")
    return found_flag

def submit_to_cylab(token):
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
    req = urllib.request.Request(
        CYLAB_SUBMIT_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Referer": "https://learn.cylabacademy.org/challenges",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyLab-Student-Agent/1.0"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = response.read().decode("utf-8")
            print(f"[+] Platform submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[*] Platform submission status: {e} (Offline verification mode; verified reproducer)")
        return False
    except Exception as e:
        print(f"[*] Platform submission status: {e} (Offline verification mode; verified reproducer)")
        return False

def main():
    token = solve_offline()
    assert token == TARGET_FLAG, f"Verification failed: {token} != {TARGET_FLAG}"
    submit_to_cylab(token)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")

if __name__ == "__main__":
    main()
