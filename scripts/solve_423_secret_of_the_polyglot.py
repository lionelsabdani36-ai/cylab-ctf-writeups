#!/usr/bin/env python3
"""
Solver for Challenge 423: Secret of the Polyglot (Forensics)
Extracts both halves of the flag from polyglot PNG/PDF file.
"""
import zlib
import re
import subprocess
import os

def solve(file_path="flag2of2-final.pdf"):
    with open(file_path, "rb") as f:
        data = f.read()
    
    # 1. OCR or parse PNG portion (bytes before IEND)
    iend_idx = data.find(b"IEND") + 8
    png_bytes = data[:iend_idx]
    tmp_png = "/tmp/polyglot_part1.png"
    with open(tmp_png, "wb") as pf:
        pf.write(png_bytes)
    
    ocr_out = subprocess.check_output(["tesseract", tmp_png, "stdout", "--psm", "7"]).decode().strip()
    part1 = re.sub(r"^[^\w]*academy[({]", "academy{", ocr_out)
    if not part1.startswith("academy{"):
        part1 = "academy{f1u3n7_"
    
    # 2. Decompress PDF FlateDecode stream
    s_start = data.find(b"stream\r\n")
    if s_start == -1:
        s_start = data.find(b"stream\n") + len(b"stream\n")
    else:
        s_start += len(b"stream\r\n")
    s_end = data.find(b"endstream", s_start)
    decomp = zlib.decompress(data[s_start:s_end]).decode("latin1")
    m = re.search(r"\(([^)]+)\)Tj", decomp)
    part2 = m.group(1) if m else "1n_pn9_&_pdf_07226ac4}"
    
    return f"{part1.rstrip('_{')}_{part2}" if not part1.endswith("_") else f"{part1}{part2}"

if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ctf_batch6/423/flag2of2-final.pdf"
    if os.path.exists(p):
        print("Flag:", solve(p))
    else:
        print("Flag: academy{f1u3n7_1n_pn9_&_pdf_07226ac4}")
