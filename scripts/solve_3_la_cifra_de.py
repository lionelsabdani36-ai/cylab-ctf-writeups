#!/usr/bin/env python3
"""Solver for Challenge 3: la cifra de (Cryptography, picoCTF 2019).

Vigenere cipher served over TCP (nc host port). Key recovery via
Kasiski + chi-squared per key position yields key FLAG (L=4).
Usage: python3 solve_3_la_cifra_de.py [host] [port]
"""
import re
import socket
import sys
from collections import Counter
from math import gcd

EN = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
      0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
      0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
      0.00978, 0.02360, 0.00150, 0.01974, 0.00074]


def fetch(host, port):
    s = socket.create_connection((host, port), timeout=20)
    s.settimeout(8)
    data = b''
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 8000:
                break
    except Exception:
        pass
    return data.decode('utf-8', errors='replace')


def crack_key(ct_letters):
    best = (1e18, '')
    for L in range(2, 13):
        key = ''
        tot = 0.0
        for j in range(L):
            col = ct_letters[j::L]
            n = len(col)
            best_k = (1e18, 0)
            for k in range(26):
                c = Counter((ord(ch) - 97 - k) % 26 for ch in col)
                x = sum((c.get(i, 0) - n * EN[i]) ** 2 / (n * EN[i])
                        for i in range(26))
                if x < best_k[0]:
                    best_k = (x, k)
            key += chr(best_k[1] + 65)
            tot += best_k[0]
        if tot < best[0]:
            best = (tot, key)
    return best[1]


def vig_dec(txt, key):
    out, ki = [], 0
    for ch in txt:
        if 'a' <= ch <= 'z':
            k = ord(key[ki % len(key)]) - 65
            out.append(chr((ord(ch) - 97 - k) % 26 + 97))
            ki += 1
        elif 'A' <= ch <= 'Z':
            k = ord(key[ki % len(key)]) - 65
            out.append(chr((ord(ch) - 65 - k) % 26 + 65))
            ki += 1
        else:
            out.append(ch)
    return ''.join(out)


def solve(host='xebec.cylabacademy.net', port=42479):
    txt = fetch(host, port)
    ct = ''.join(re.findall(r'[A-Za-z]', txt)).lower()
    key = crack_key(ct)
    pt = vig_dec(txt, key)
    m = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', pt)
    return m.group(1) if m else 'Flag not found (key=%s)' % key


if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else 'xebec.cylabacademy.net'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 42479
    print('Flag:', solve(host, port))
