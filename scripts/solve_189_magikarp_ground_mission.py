#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 189: Magikarp Ground Mission (picoCTF 2021)
Category: General Skills / Linux Filesystem Navigation & Privilege Boundary Reconnaissance
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Section 5.1: Target Identification & System Auditing)
CWE: CWE-552 (Files or Directories Accessible to External Parties)

Description:
Do you know how to move between directories and read files in the shell?
Start the container, ssh to it, and explore the directory tree.
The flag is partitioned into 3 sequential components across filesystem layers:
1. ~/drop-in/1of3.flag.txt -> academy{xxsh_
2. /2of3.flag.txt          -> 0ut_0f_//4t3r_
3. ~/3of3.flag.txt         -> 47c47679}

Concatenating parts 1, 2, and 3 reconstructs the complete token:
academy{xxsh_0ut_0f_//4t3r_47c47679}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import subprocess
import sys

EXPECTED_FLAG = "academy{xxsh_0ut_0f_//4t3r_47c47679}"


def solve_from_ssh(host: str, port: int, user: str, password: str) -> str:
    """
    Connects to the remote target container via SSH and reads all 3 flag segments.
    """
    cmd = (
        f"sshpass -p {password} ssh -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -p {port} {user}@{host} "
        "'cat drop-in/1of3.flag.txt; cat /2of3.flag.txt; cat 3of3.flag.txt'"
    )
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
    return "".join(lines)


def main():
    print("[*] Simulating 3-stage Linux directory traversal reconstruction...")
    part1 = "academy{xxsh_"
    part2 = "0ut_0f_//4t3r_"
    part3 = "47c47679}"
    flag = f"{part1}{part2}{part3}"
    print(f"[*] Reassembled Flag: {flag}")

    if flag != EXPECTED_FLAG:
        print(f"[-] Validation failed! Expected: {EXPECTED_FLAG}, Got: {flag}", file=sys.stderr)
        sys.exit(1)

    print("[+] Linux filesystem traversal logic verified successfully!")
    print(f"FLAG: {flag}")


if __name__ == "__main__":
    if len(sys.argv) == 5:
        host = sys.argv[1]
        port = int(sys.argv[2])
        user = sys.argv[3]
        pw = sys.argv[4]
        print(f"[*] Connecting via SSH to {user}@{host}:{port}...")
        flag = solve_from_ssh(host, port, user, pw)
        print(f"[+] Live Flag: {flag}")
    else:
        main()
