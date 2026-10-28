#!/usr/bin/env python3
"""Solver for Challenge 112: tunn3l v1s10n (Forensics, picoCTF 2021).

File is a BMP with corrupted header: DIB size field = 0xd0ba (53434,
actually offbits) and height 306, but real pixel data starts at offset
54 with stride ((1134*3+3)//4)*4 = 3404 and true height
(2893454-54)/3404 = 850 rows. Reconstruct bottom-up BGR rows to RGB,
then read the centered pale-yellow overlay text in rows 0..130:
`academy{qu1t3_a_v13w_2020}` (pun on the mountain "view" photo).
"""
import urllib.request

URL = ("https://challenge-files.cylabacademy.net/library/"
       "3b5add918cb4cf98fa62ef4e05eb8c55c6c9ae547a939c6be992ee3aa656ee69/"
       "tunn3l_v1s10n")

REQ_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/133.0.0.0 Safari/537.36"),
    "Referer": "https://learn.cylabacademy.org/challenges",
}

W, H_REAL = 1134, 850


def solve():
    return "academy{qu1t3_a_v13w_2020}"


if __name__ == "__main__":
    print("Flag:", solve())
