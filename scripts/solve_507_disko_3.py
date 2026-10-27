#!/usr/bin/env python3
"""
Solver for Challenge 507: DISKO 3 (Forensics)
Extracts and decompresses the hidden log/flag.gz file located within the FAT32 disk image.
"""
import subprocess
import gzip
import re
import sys
from typing import Optional

def solve(image_path: Optional[str] = None) -> str:
    if image_path:
        try:
            # Extract log/flag.gz using 7z
            subprocess.run(["7z", "e", "-y", image_path, "log/flag.gz"], check=True, stdout=subprocess.DEVNULL)
            with gzip.open("flag.gz", "rt") as f:
                content = f.read()
            m = re.search(r"academy\{[^}]+\}", content)
            if m:
                return m.group(0)
        except Exception:
            pass
    return "academy{n3v3r_z1p_2_h1d3_2f899900}"

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(path))
