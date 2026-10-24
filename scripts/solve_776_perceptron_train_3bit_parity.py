#!/usr/bin/env python3
"""
Automated Solver for Challenge 776: Perceptron Train 3-Bit Parity (CyLab Security Academy)
Demonstrates the non-linear separability ceiling in 3D space by tuning learning rate to reach 75% accuracy.
"""

import sys
import json
import urllib.request

def solve(base_url="http://chatelaine.cylabacademy.net:45398"):
    url = f"{base_url.rstrip('/')}/train"
    print(f"[*] Sweeping learning rates against {url}...")
    for lr_int in range(2, 2000, 2):
        lr = round(lr_int * 0.01, 2)
        req = urllib.request.Request(
            url,
            data=json.dumps({"learningRate": lr}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
                if data.get("accuracy") >= 0.75 or data.get("flag"):
                    print(f"[+] Found converging rate: lr={lr}, acc={data.get('accuracy')}")
                    flag = data.get("flag")
                    if flag:
                        print(f"[!] EXTRACTED FLAG: {flag}")
                        return flag
        except Exception as e:
            pass

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://chatelaine.cylabacademy.net:45398"
    solve(target)
