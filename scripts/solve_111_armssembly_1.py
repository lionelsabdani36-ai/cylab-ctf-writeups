#!/usr/bin/env python3
"""Solver for Challenge 111: ARMssembly 1 (Reverse Engineering).

chall_1.S: func(arg): a=60, b=0, c=3; tmp=(a<<b)=60; tmp=tmp//c=20;
tmp=tmp-arg=20-arg. main prints "win" iff func(x)==0 -> x=20.
Flag format: academy{XXXXXXXX} hex lowercase no 0x, 32 bits.
20 = 0x14 -> '00000014'.
"""
import urllib.request

URL = ("https://challenge-files.cylabacademy.net/library/"
       "faf1dc0995a3edfb49290cb451b6c151521d8979a6b05fb4220e313b49a709a1/"
       "chall_1.S")

REQ_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/133.0.0.0 Safari/537.36"),
    "Referer": "https://learn.cylabacademy.org/challenges",
}


def solve():
    # a=60, b=0, c=3 -> (60<<0)//3 = 20 -> arg=20 -> hex 32-bit
    return "academy{%08x}" % 20


if __name__ == "__main__":
    print("Flag:", solve())
