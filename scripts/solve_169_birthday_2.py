#!/usr/bin/env python3
"""Solver for Challenge 169 It is my Birthday 2 (picoCTF 2021, Cryptography).

Server asks for 2 different but valid PDFs with identical SHA1, both
sharing the invite's last 1000 bytes. Classic SHAttered chosen-prefix
collision: download the public shattered-1.pdf / shattered-2.pdf pair
(same SHA1 38762cf7..., different content), append the invite's last
1000 bytes to BOTH (Merkle-Damgard length-extension preserves the
collision and equalizes the tails), then POST multipart to /upload.
The index page flashes the flag.

Usage: solve_169_birthday_2.py [host] [port]
Verified: academy{h4ppy_b1rthd4y_2_m3_8248ffdd} (POST /api/submissions/ -> correct:true)
"""
import hashlib
import re
import socket
import sys
import urllib.request

HOST = "chatelaine.cylabacademy.net"
PORT = 31494
SHATTERED = ("https://shattered.io/static/shattered-1.pdf",
             "https://shattered.io/static/shattered-2.pdf")
INVITE_URL = ("https://challenge-files.cylabacademy.net/library/"
              "950f16ca2ee02dd184916ff9f2e20282d307309dffd6cc46bdc0bc61104bf490/"
              "invite.pdf")
BOUND = "BOUNDARY169b24xyz"
EXPECTED = "academy{h4ppy_b1rthd4y_2_m3_8248ffdd}"
FLAG_RE = re.compile(r"academy\{[^}]*\}|picoCTF\{[^}]*\}")


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def raw_send(host, port, head: bytes, body: bytes = b""):
    s = socket.create_connection((host, int(port)), timeout=60)
    try:
        s.sendall(head + body)
        data = b""
        while True:
            ch = s.recv(16384)
            if not ch:
                break
            data += ch
    finally:
        s.close()
    h, _, b = data.partition(b"\r\n\r\n")
    return h.decode(errors="replace"), b.decode(errors="replace")


def solve(host: str = HOST, port: int = PORT) -> str:
    invite = fetch(INVITE_URL)
    tail = invite[-1000:]
    print("[*] invite %d bytes, tail %d bytes" % (len(invite), len(tail)))
    pdfs = []
    for url in SHATTERED:
        base = fetch(url)
        pdfs.append(base + tail)
    h1 = hashlib.sha1(pdfs[0]).hexdigest()
    assert h1 == hashlib.sha1(pdfs[1]).hexdigest(), "collision broken"
    assert pdfs[0] != pdfs[1], "files identical"
    print("[*] collision sha1:", h1)
    parts = []
    for i, (field, data) in enumerate(
            (("file1", pdfs[0]), ("file2", pdfs[1]))):
        parts.append(
            ("--" + BOUND + "\r\nContent-Disposition: form-data; "
             'name="%s"; filename="upload%d.pdf"\r\n'
             "Content-Type: application/pdf\r\n\r\n" % (field, i + 1)
             ).encode() + data + b"\r\n")
    parts.append(("--" + BOUND + "--\r\n").encode())
    body = b"".join(parts)
    h = (("POST /upload HTTP/1.0\r\nHost: x\r\nUser-Agent: Mozilla/5.0\r\n"
          "Content-Type: multipart/form-data; boundary=%s\r\n"
          "Content-Length: %d\r\n\r\n" % (BOUND, len(body))).encode())
    head, _ = raw_send(host, port, h, body)
    ck = next((l.split(":", 1)[1].strip().split(";")[0]
               for l in head.split("\r\n")
               if l.lower().startswith("set-cookie:")), "")
    h2 = (("GET / HTTP/1.0\r\nHost: x\r\nUser-Agent: Mozilla/5.0\r\n" +
           ("Cookie: " + ck + "\r\n" if ck else "") + "\r\n").encode())
    _, page = raw_send(host, port, h2)
    m = FLAG_RE.search(page)
    if not m:
        raise ValueError("flag not in index page")
    flag = m.group(0)
    print("flag:", flag)
    assert flag == EXPECTED, flag
    return flag


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(solve(host, port))
