#!/usr/bin/env python3
"""
Solver for Challenge 406: Bookmarklet (Web Exploitation)
Reverses the client-side JavaScript bookmarklet decryption routine.
"""
import urllib.request
import re
import sys

from typing import Optional

def decrypt_bookmarklet(encrypted_flag: str, key: str = "picoctf") -> str:
    decrypted = ""
    for i in range(len(encrypted_flag)):
        dec = (ord(encrypted_flag[i]) - ord(key[i % len(key)]) + 256) % 256
        decrypted += chr(dec)
    return decrypted

def solve(url: Optional[str] = None) -> str:
    if url:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                html = resp.read().decode("utf-8")
                m = re.search(r'var encryptedFlag = "([^"]+)";', html)
                if m:
                    return decrypt_bookmarklet(m.group(1))
        except Exception:
            pass
    # Fallback to known encrypted string from Challenge 406
    raw_enc = "ÑÌÄÓÈáßëÙ£Ö\x96ÓÚåÛÑ¢ÕÓÌ¡\x9b\x9c\xa0\x9c¬\x9bí"
    return decrypt_bookmarklet(raw_enc)

if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(target_url)
    print("Flag:", flag)
