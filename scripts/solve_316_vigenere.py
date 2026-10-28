#!/usr/bin/env python3
"""
Solver for Challenge 316: Vigenere (Cryptography)
Decrypts cipher.txt with key CYLAB. The key index advances only
on alphabetic characters (classic Vigenere sync rule).
"""
import time
import urllib.request

URL = ("https://challenge-files.cylabacademy.net/library/"
       "1415ede8e9f58b36fddf7b520d73c151a53ac100c7a19f9b901100d3/"
       "cipher.txt")
KEY = "CYLAB"

REQ_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/133.0.0.0 Safari/537.36"),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://learn.cylabacademy.org/challenges",
}


def decrypt(cipher, key=KEY):
    out, ki = "", 0
    for ch in cipher:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            k = ord(key[ki % len(key)].upper()) - 65
            out += chr((ord(ch) - base - k) % 26 + base)
            ki += 1
        else:
            out += ch
    return out


def solve(url=URL):
    last = None
    for i in range(5):
        try:
            req = urllib.request.Request(url, headers=REQ_HEADERS)
            with urllib.request.urlopen(req, timeout=60) as resp:
                cipher = resp.read().decode().strip()
            return decrypt(cipher)
        except Exception as e:
            last = e
            time.sleep(10 * (i + 1))
    raise RuntimeError(f"fetch failed: {last}")


if __name__ == "__main__":
    print("Flag:", solve())
