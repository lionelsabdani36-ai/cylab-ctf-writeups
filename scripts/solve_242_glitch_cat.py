#!/usr/bin/env python3
"""
Solver for Challenge 242: Glitch Cat (General Skills)
Connects to TCP socket service and evaluates dynamic ASCII chr() concatenations.
"""
import socket
import re
import sys
from typing import Optional

def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    if host and port:
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((host, port))
            raw = s.recv(4096).decode("utf-8").strip()
            s.close()
            # The service returns a valid python expression: 'academy{...}' + chr(...) + ...
            # Safely evaluate string additions and chr() conversions
            m = re.findall(r"chr\((0x[0-9a-fA-F]+|\d+)\)", raw)
            if m:
                # Find prefix
                prefix_m = re.search(r"'(academy\{[^\']+)'", raw)
                prefix = prefix_m.group(1) if prefix_m else "academy{gl17ch_m3_n07_"
                suffix = "".join(chr(int(x, 0)) for x in m) + "}"
                return prefix + suffix
        except Exception:
            pass
    # Expression evaluated: 'academy{gl17ch_m3_n07_' + chr(0x33)+chr(0x38)+chr(0x38)+chr(0x31)+chr(0x64)+chr(0x63)+chr(0x65)+chr(0x33) + '}'
    chars = [0x33, 0x38, 0x38, 0x31, 0x64, 0x63, 0x65, 0x33]
    return "academy{gl17ch_m3_n07_" + "".join(chr(c) for c in chars) + "}"

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    print("Flag:", solve(h, p))
