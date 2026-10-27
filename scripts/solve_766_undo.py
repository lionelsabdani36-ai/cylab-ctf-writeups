#!/usr/bin/env python3
"""
Automated Solver for Challenge 766: Undo (Text Transformations)
"""
import socket
import re
import sys

def solve(host="xebec.cylabacademy.net", port=28696):
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, int(port)))

    def recv_until(sock, markers=[':', '?', '$', '>']):
        buf = ''
        while True:
            try:
                chunk = sock.recv(1024).decode('utf-8', errors='ignore')
                if not chunk:
                    break
                buf += chunk
                for m in markers:
                    if buf.endswith(m) or buf.endswith(m + ' '):
                        return buf
                if 'academy{' in buf or 'picoCTF{' in buf:
                    return buf
            except socket.timeout:
                break
        return buf

    while True:
        prompt = recv_until(s)
        print(prompt)
        if 'academy{' in prompt or 'picoCTF{' in prompt:
            break
        
        hint_match = re.search(r'Hint:\s*([^\n]+)', prompt)
        hint = hint_match.group(1).lower() if hint_match else ''
        cmd = ''
        if 'base64' in hint:
            cmd = 'base64 -d'
        elif 'reversed' in hint or 'reverse' in hint:
            cmd = 'rev'
        elif 'rot13' in hint or 'rot 13' in hint or 'caesar' in hint:
            cmd = "tr 'A-Za-z' 'N-ZA-Mn-za-m'"
        elif 'curly braces with parentheses' in hint:
            cmd = "tr '()' '{}'"
        elif 'underscores with dashes' in hint:
            cmd = "tr '-' '_'"
        
        s.sendall(f"{cmd}\n".encode())

    s.close()

if __name__ == "__main__":
    solve()
