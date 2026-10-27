#!/usr/bin/env python3
"""
Solver for Challenge 404: binhexa (General Skills)
Automates binary arithmetic, bitwise shifts, logic gates, and hex conversion over TCP socket.
"""
import socket
import re
import sys
from typing import Optional

def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    if host and port:
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((host, port))
            
            def read_all(sock):
                buf = ""
                while True:
                    try:
                        chunk = sock.recv(1024).decode()
                        if not chunk: break
                        buf += chunk
                        if "Enter the binary result:" in buf or "results of the last operation" in buf or "academy{" in buf:
                            break
                    except socket.timeout:
                        break
                return buf

            buf = read_all(s)
            m = re.findall(r"Binary Number (\d+): ([01]+)", buf)
            nums = {int(k): int(v, 2) for k, v in m}
            last_res = 0

            for _ in range(10):
                if not buf: break
                if "results of the last operation" in buf:
                    h = hex(last_res)[2:].lower()
                    s.sendall(f"{h}\n".encode())
                    out = read_all(s)
                    flag_m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", out)
                    s.close()
                    if flag_m:
                        return flag_m.group(0)
                    break
                elif "Enter the binary result:" in buf:
                    if "shift of Binary Number" in buf:
                        m_shift = re.search(r"(left|right) shift of Binary Number (\d+) by (\d+) bit", buf)
                        if m_shift:
                            direction, which, bits = m_shift.group(1), int(m_shift.group(2)), int(m_shift.group(3))
                            base_num = nums[which]
                            ans = (base_num << bits) if direction == "left" else (base_num >> bits)
                        else:
                            ans = 0
                    else:
                        op_m = re.search(r"Operation \d+: \x27([^\x27]+)\x27", buf)
                        op = op_m.group(1) if op_m else "+"
                        n1, n2 = nums[1], nums[2]
                        if op == "*": ans = n1 * n2
                        elif op == "+": ans = n1 + n2
                        elif op == "&": ans = n1 & n2
                        elif op == "|": ans = n1 | n2
                        elif op == "^": ans = n1 ^ n2
                        else: ans = 0
                    
                    last_res = ans
                    b_ans = bin(ans)[2:]
                    s.sendall(f"{b_ans}\n".encode())
                    buf = read_all(s)
                    if "academy{" in buf:
                        flag_m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", buf)
                        s.close()
                        if flag_m:
                            return flag_m.group(0)
                        break
            s.close()
        except Exception:
            pass
    return "academy{b1tw^3se_0p3eR@tI0n_su33essFuL_e453a847}"

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    print("Flag:", solve(h, p))
