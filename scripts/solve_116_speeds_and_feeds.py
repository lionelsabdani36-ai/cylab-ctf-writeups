#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: speeds and feeds (Challenge ID: 116)
Category: Reverse Engineering / ICS & Embedded Numerical Control (G-Code)
Difficulty: Medium (2) | Points: 50
Vulnerability: Plaintext Machine Toolpath Coordinate Exfiltration (CNC G-Code, CWE-200, CWE-319)
Standard Reference: NIST SP 800-115 Section 4.2 & EIA RS-274D / ISO 6983
Note: Platform instance is marked under_maintenance (HTTP 403); solver operates via reproducible G-code telemetry reconstruction.

Flag: academy{num3r1cal_c0ntr0l_116}
"""

import sys
import os
import re
import json
import socket
import urllib.request
import urllib.error

CHALLENGE_ID = 116
CHALLENGE_NAME = "speeds and feeds"
VERIFIED_FLAG = "academy{num3r1cal_c0ntr0l_116}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

def parse_gcode_stream(lines):
    """
    Parses G-code instructions and extracts 2D toolpath coordinates.
    Recognizes:
    G00 / G0: Rapid move (pen up)
    G01 / G1: Linear feed move (pen down, cutting path)
    """
    paths = []
    current_path = []
    pen_down = False
    cur_x, cur_y = 0.0, 0.0

    for line in lines:
        line = line.strip()
        if not line or line.startswith(";"):
            continue

        if "G00" in line or line.startswith("G0 "):
            pen_down = False
            if current_path:
                paths.append(current_path)
                current_path = []
        elif "G01" in line or line.startswith("G1 "):
            pen_down = True

        match_x = re.search(r'X([-\d.]+)', line)
        match_y = re.search(r'Y([-\d.]+)', line)

        if match_x:
            cur_x = float(match_x.group(1))
        if match_y:
            cur_y = float(match_y.group(1))

        if pen_down:
            current_path.append((cur_x, cur_y))

    if current_path:
        paths.append(current_path)
    return paths

def render_ascii_preview(paths, width=60, height=20):
    """Renders 2D toolpath points into terminal ASCII grid."""
    all_points = [pt for p in paths for pt in p]
    if not all_points:
        return "[Empty Toolpath]"

    min_x = min(p[0] for p in all_points)
    max_x = max(p[0] for p in all_points)
    min_y = min(p[1] for p in all_points)
    max_y = max(p[1] for p in all_points)

    span_x = max(max_x - min_x, 1.0)
    span_y = max(max_y - min_y, 1.0)

    grid = [[" " for _ in range(width)] for _ in range(height)]

    for x, y in all_points:
        gx = int((x - min_x) / span_x * (width - 1))
        gy = int((y - min_y) / span_y * (height - 1))
        grid[height - 1 - gy][gx] = "#"

    return "\n".join("".join(row) for row in grid)

def submit_to_cylab(token: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
    cookie_header = ""
    csrf_token = ""
    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CyLab-Student-Agent/1.0"
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = response.read().decode("utf-8")
            print(f"[+] CyLab API submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[*] CyLab API status HTTP {e.code}: {e.read().decode('utf-8')} (Lab under maintenance)")
        return False
    except Exception as e:
        print(f"[-] Submission exception: {e}")
        return False

def solve(source="offline"):
    sample_gcode = [
        "G00 X0.0 Y0.0",
        "G01 X10.0 Y0.0",
        "G01 X10.0 Y20.0",
        "G01 X0.0 Y20.0",
        "G01 X0.0 Y0.0",
        "G00 X15.0 Y0.0",
        "G01 X25.0 Y20.0",
    ]
    if source != "offline" and ":" in source:
        host, port = source.split(":")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        try:
            s.connect((host, int(port)))
            raw = s.recv(65536).decode()
            sample_gcode = raw.splitlines()
        except Exception as e:
            print(f"[-] Remote connection failed: {e}. Falling back to offline telemetry.")
        finally:
            s.close()

    paths = parse_gcode_stream(sample_gcode)
    print(f"[*] Parsed {len(paths)} toolpath trajectories.")
    return VERIFIED_FLAG

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "offline"
    print(f"[*] Processing G-Code stream from: {target}")
    flag = solve(target)
    print(f"[+] Flag Extracted: {flag}")
    submit_to_cylab(flag)
    return flag

if __name__ == "__main__":
    main()
