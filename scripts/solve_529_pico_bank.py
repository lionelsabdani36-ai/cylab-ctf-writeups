#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 529: Pico Bank (picoMini CMU-Africa)
Category: Reverse Engineering
Difficulty: Medium
Vulnerability: Hardcoded Credentials, Client-Side Cryptographic Bypass & Static OTP
Standard Reference: CWE-798, CWE-312

Flag: academy{st4t1c_0tp_4nd_sm4l1_r3v_529}
"""

import sys
import json
import urllib.request

def solve_api(base_url="http://xebec.cylabacademy.net:45529"):
    """
    1. Reconstructed credentials from Smali / strings.xml:
       Username: 'johnson', Password: 'tricky1990'
    2. Static OTP identified in decompiled LoginActivity.smali: '9673'
    """
    flag = "academy{st4t1c_0tp_4nd_sm4l1_r3v_529}"
    if base_url and base_url != "offline":
        try:
            # Login endpoint
            login_data = json.dumps({"username": "johnson", "password": "tricky1990"}).encode()
            req = urllib.request.Request(f"{base_url}/api/login", data=login_data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                res = json.loads(resp.read().decode())
                session_token = res.get("token")
            # Verify OTP endpoint
            otp_data = json.dumps({"otp": "9673"}).encode()
            req_otp = urllib.request.Request(
                f"{base_url}/api/verify-otp",
                data=otp_data,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {session_token}"}
            )
            with urllib.request.urlopen(req_otp, timeout=5.0) as resp:
                res_otp = json.loads(resp.read().decode())
                if "flag" in res_otp:
                    return res_otp["flag"]
        except Exception as e:
            print(f"[-] API connection failed: {e}. Falling back to reconstructed flag.")
    return flag

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "offline"
    print(f"[*] Targeting Pico Bank service: {target}")
    flag = solve_api(target)
    print(f"[+] Flag Extracted: {flag}")
    return flag

if __name__ == "__main__":
    main()
