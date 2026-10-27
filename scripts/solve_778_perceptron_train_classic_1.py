#!/usr/bin/env python3
"""
Automated Solver for Challenge 778: Perceptron Train Classic 1 (CyLab Security Academy)
Sweeps learning rates to accumulate 5 successful 100% accuracy runs in the same session.
"""

import sys
import json
import urllib.request
import http.cookiejar

def solve(base_url="http://chatelaine.cylabacademy.net:36775"):
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    
    # Initialize session
    cfg_url = f"{base_url.rstrip('/')}/config.json"
    with opener.open(cfg_url) as resp:
        cfg = json.loads(resp.read().decode())
        print(f"[*] Loaded config from {cfg_url}: target={cfg.get('successTarget')}")
        
    train_url = f"{base_url.rstrip('/')}/train"
    successes = []
    
    for lr_int in range(2, 2000, 2):
        lr = round(lr_int * 0.01, 2)
        req = urllib.request.Request(
            train_url,
            data=json.dumps({"learningRate": lr}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with opener.open(req) as resp:
            data = json.loads(resp.read().decode())
            if data.get("accuracy") == 1.0:
                successes.append((lr, data.get("successCount")))
                print(f"[+] Success #{len(successes)}: lr={lr}, count={data.get('successCount')}")
                if data.get("flag"):
                    flag = data.get("flag")
                    print(f"[!] EXTRACTED FLAG: {flag}")
                    return flag
            if len(successes) >= 5 and data.get("flag"):
                flag = data.get("flag")
                print(f"[!] EXTRACTED FLAG: {flag}")
                return flag

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://chatelaine.cylabacademy.net:36775"
    solve(target)
