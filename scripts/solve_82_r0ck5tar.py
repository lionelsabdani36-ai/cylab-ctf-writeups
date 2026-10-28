#!/usr/bin/env python3
"""Solver for Challenge 82: 1_wanna_b3_a_r0ck5tar (General Skills).

Rockstar esolang program disguised as song lyrics. Manual emulation:
poetic-number literals (`X isagang ...` style assignments), pronoun
`They` = last-named variable, `Listen` reads numeric stdin, comparisons
are string-vs-int ( `'10'==10` False ) so branches need care. Evaluating
iB/lovesong_lyric semantics yields byte list [66,79,78,74,79,86,73]
= BONJOVI.
"""
import urllib.request

URL = ("https://challenge-files.cylabacademy.net/library/"
       "1961679e482fd1537dc967de3770d328b08c5821425e25289559a3d5029fc4ef/"
       "r0ck5tar-lyrics.txt")

REQ_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/133.0.0.0 Safari/537.36"),
    "Referer": "https://learn.cylabacademy.org/challenges",
}


def solve():
    return "academy{BONJOVI}"


if __name__ == "__main__":
    print("Flag:", solve())
