#!/usr/bin/env python3
"""
Automated Solver for Challenge 782: Perceptron Train XOR (CyLab Security Academy)
Exploits the /train endpoint by tuning learning rate to achieve the theoretical 75% limit.
"""

import sys
import json
import urllib.request

def solve(base_url="http://xebec.cylabacademy.net:22064"):
    url = f"{base_url.rstrip('/')}/train"
    print(f"[*] Posting training request to {url} with learningRate=0.02...")
    req = urllib.request.Request(
        url,
        data=json.dumps({"learningRate": 0.02}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        print(f"[+] Response status: acc={data.get('accuracy')}, success={data.get('success')}")
        flag = data.get("flag")
        if flag:
            print(f"[+] EXTRACTED FLAG: {flag}")
            return flag
        else:
            print(f"[-] No flag returned: {data}")
            return None

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://xebec.cylabacademy.net:22064"
    solve(target)
