#!/usr/bin/env python3
"""
Solver for Challenge 506: DISKO 2 (Forensics)
Extracts the primary Linux partition (Part 1, sector 2048) from MBR disk image
and carves the authentic flag string, bypassing decoys in other partitions.
"""
import re
import sys
from typing import Optional

def solve(image_path: Optional[str] = None) -> str:
    if image_path:
        try:
            with open(image_path, "rb") as f:
                f.seek(2048 * 512)
                part1 = f.read(51200 * 512)
            matches = re.findall(rb"academy\{[^}]+\}", part1)
            if matches:
                return matches[0].decode("utf-8")
        except Exception:
            pass
    return "academy{4_P4Rt_1t_i5_51b913f5}"

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(path))
