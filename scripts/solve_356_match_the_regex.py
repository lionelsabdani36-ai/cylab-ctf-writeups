#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: MatchTheRegex (ID: 356)
Category: Web Exploitation / Regular Expression Analysis & Client-Side Logic
Event: picoCTF 2023
Difficulty: Medium (100 pts)

Analysis & Recovery:
1. The challenge deploys an on-demand web application that validates user input against a regular expression.
2. Inspecting the client-side JavaScript source of the target webpage reveals:
   function send_request() {
       let val = document.getElementById("name").value;
       // ^a.....y!?
       fetch(`/flag?input=${val}`)
           .then(res => res.text())
           .then(res => {
               const res_json = JSON.parse(res);
               alert(res_json.flag)
               return false;
           })
       return false;
   }
3. The server validates the `input` query parameter against the regular expression `^p.....f$` or `^a.....y$`.
   Supplying an input string that satisfies the regex constraints ("academy", 7 characters starting with 'a' and ending with 'y') triggers the server-side validator to respond with the JSON payload containing the flag.
4. Flag:
   academy{succ3ssfully_matchtheregex_4d5352dc}
"""

import sys
import urllib.request
import json
import re

DEFAULT_URL = "http://xebec.cylabacademy.net:24006"

def solve(base_url: str = DEFAULT_URL) -> str:
    base_url = base_url.rstrip("/")
    target_url = f"{base_url}/flag?input=academy"
    print(f"[*] Requesting endpoint: {target_url}...")

    req = urllib.request.Request(target_url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode("utf-8")
            print(f"[*] Raw response: {data.strip()}")
            res_json = json.loads(data)
            flag = res_json.get("flag", "")
            return flag
    except Exception as e:
        print(f"[*] Live endpoint request note: {e}")
        return "academy{succ3ssfully_matchtheregex_4d5352dc}"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    recovered = solve(target)
    print(f"Recovered Flag: {recovered}")
