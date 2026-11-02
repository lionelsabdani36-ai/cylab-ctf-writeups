#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: Event-Viewing (ID: 456)
Category: Forensics / Windows Event Log (.evtx) Analysis & Malware Persistence
Event: picoCTF 2025
Difficulty: Medium (200 pts)

Analysis & Recovery:
1. Challenge provides Windows_Logs.evtx detailing a compromised workstation infection chain:
   - Step 1: Installer execution (Totally_Legit_Software.msi). MsiInstaller records installation
     parameters with embedded base64 token: YWNhZGVteXtFdjNudF92aTN3djNyXw== -> academy{Ev3nt_vi3wv3r_
   - Step 2: Malware execution creates a persistent Run key in Windows Registry targeting
     custom_shutdown.exe. The registry operation description logs the reason containing base64 token:
     MXNfYV9wcjN0dHlfdXMzZnVsXw== -> 1s_a_pr3tty_us3ful_
   - Step 3: At user logon, custom_shutdown.exe triggers system shutdown (User32 Event 1074).
     The shutdown reason string stores the final base64 token:
     dDAwbF84MWJhM2ZlOX0= -> t00l_81ba3fe9}
2. EVTX binary chunks contain UTF-16LE text records at both even and odd byte alignments.
   Scanning the stream across 0 and 1 byte offsets recovers all 3 base64 tokens deterministically.
3. Concatenating all 3 decoded parts yields the complete flag:
   academy{Ev3nt_vi3wv3r_1s_a_pr3tty_us3ful_t00l_81ba3fe9}
"""

import os
import re
import base64
import urllib.request

LOG_URL = "https://challenge-files.cylabacademy.net/library/ce601bcb71ad064088b71881564ee20ccdc62d9ec1dc7519d06b758a2e1f1efa/Windows_Logs.evtx"

def solve(evtx_path: str = "") -> str:
    if not evtx_path or not os.path.exists(evtx_path):
        work_dir = os.path.join(os.environ.get("TMPDIR", "/home/lionelsabdani36/.hermes/cache/scratch"), "solve_456")
        os.makedirs(work_dir, exist_ok=True)
        evtx_path = os.path.join(work_dir, "Windows_Logs.evtx")
        if not os.path.exists(evtx_path):
            print(f"[*] Downloading {LOG_URL}...")
            urllib.request.urlretrieve(LOG_URL, evtx_path)

    print(f"[*] Scanning {evtx_path} for UTF-16LE forensic event artifacts...")
    with open(evtx_path, "rb") as f:
        data = f.read()

    tokens = {}
    for offset in (0, 1):
        txt = data[offset:].decode("utf-16le", "ignore")
        for m in re.finditer(r"(?:YWNhZGVte|MXNfYV|dDAwbF)[A-Za-z0-9+/]*={1,2}", txt):
            tok = m.group(0)
            try:
                dec = base64.b64decode(tok).decode("latin-1")
                if dec.startswith("academy{"):
                    tokens[1] = dec
                elif dec.endswith("}"):
                    tokens[3] = dec
                else:
                    tokens[2] = dec
            except Exception:
                pass

    print(f"[*] Recovered tokens: {tokens}")
    if len(tokens) < 3:
        raise RuntimeError(f"Failed to recover all 3 tokens: {tokens}")

    flag = f"{tokens[1]}{tokens[2]}{tokens[3]}"
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"Recovered Flag: {flag}")
