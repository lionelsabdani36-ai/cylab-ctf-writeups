#!/usr/bin/env python3
"""Solver for Challenge 290 Redaction gone wrong (picoCTF 2022, Forensics).

Vuln: PDF "redaction" only paints a black rect over the flag text
(`0 0 0 rg / n 69 428 192.096 17 re f*`); the Tj string stays in the
content stream (ASCII85+Flate). Decode stream -> read flag.

Usage: solve_290_redaction.py [pdf path]
Verified: academy{C4n_Y0u_S33_m3_fully} (POST /api/submissions/ -> correct:true)
"""
import base64
import re
import sys
import zlib

EXPECTED = "academy{C4n_Y0u_S33_m3_fully}"


def solve(path: str) -> str:
    data = open(path, "rb").read()
    m = re.search(rb"stream\r?\n(.*?)endstream", data, re.S)
    raw = m.group(1).strip()
    dec = base64.a85decode(raw, adobe=True) if raw.endswith(b"~>") else base64.a85decode(raw)
    text = zlib.decompress(dec).decode("latin1")
    m2 = re.search(r"academy\{[^}]*\}", text)
    flag = m2.group(0)
    print(flag)
    return flag


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "Financial_Report_for_ABC_Labs.pdf"))
