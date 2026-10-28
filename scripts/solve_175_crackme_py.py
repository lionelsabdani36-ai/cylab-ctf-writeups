#!/usr/bin/env python3
"""
Solver for Challenge 175: crackme-py (Reverse Engineering)
Applies ROT47 (involution over 94 printable ASCII chars) to the
embedded bezos_cc_secret, mirroring decode_secret() in crackme_gen.py.
"""
import urllib.request

URL = ("https://challenge-files.cylabacademy.net/library/"
       "1eb77f4c882ea622da246f47b4359567016b003c1856cdd9c58d7e5d95b/"
       "crackme_gen.py")
ALPHABET = ("!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")
SECRET = "24256>JL`>0c0Abc?FE02a_53e7fe7af5gN"


def rot47(text):
    return "".join(ALPHABET[(ALPHABET.find(c) + 47) % len(ALPHABET)]
                   for c in text)


def solve():
    return rot47(SECRET)


if __name__ == "__main__":
    print("Flag:", solve())
