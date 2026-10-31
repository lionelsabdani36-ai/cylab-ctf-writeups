#!/usr/bin/env python3
"""Solver for Challenge 751 Hidden Cipher 2 (picoCTF 2026, Reverse Engineering).

Binary asks a math question (addition, subtraction, multiplication),
validates the answer, and if correct, encodes each flag character by
multiplying its ASCII code by the math answer:
    encoded[i] = flag[i] * answer
The encoded values are printed as space-separated integers.
Decoding recovers the original ASCII character via integer division:
    flag[i] = encoded[i] // answer

Verified: academy{m4th_b3h1nd_c1ph3r_3c573aef} (POST /api/submissions/ -> correct:true)
"""
import re
import socket
import sys

HOST = "xebec.cylabacademy.net"
PORT = 18581
EXPECTED = "academy{m4th_b3h1nd_c1ph3r_3c573aef}"


def solve_interactive(host: str, port: int, timeout: int = 15) -> str:
    s = socket.create_connection((host, int(port)), timeout=timeout)
    buf = b""
    try:
        while b"?" not in buf:
            chunk = s.recv(1024)
            if not chunk:
                break
            buf += chunk

        prompt = buf.decode()
        m = re.search(r"What is (\d+)\s*([\+\-\*])\s*(\d+)\?", prompt)
        if not m:
            raise ValueError(f"Could not parse math prompt: {prompt}")

        n1, op, n2 = int(m.group(1)), m.group(2), int(m.group(3))
        if op == "+":
            ans = n1 + n2
        elif op == "-":
            ans = n1 - n2
        elif op == "*":
            ans = n1 * n2
        else:
            raise ValueError(f"Unknown operator: {op}")

        s.sendall(f"{ans}\n".encode())

        resp = b""
        while True:
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                resp += chunk
            except Exception:
                break

        resp_str = resp.decode()
        nums = [
            int(x)
            for x in re.findall(
                r"-?\d+", resp_str.split("Encoded flag values:")[-1]
            )
        ]
        flag = "".join(chr(x // ans) for x in nums)
        return flag
    finally:
        s.close()


def decode_static(numbers: list, answer: int) -> str:
    return "".join(chr(x // answer) for x in numbers)


if __name__ == "__main__":
    if len(sys.argv) > 2:
        print(solve_interactive(sys.argv[1], int(sys.argv[2])))
    else:
        sample_nums = [
            7857, 8019, 7857, 8100, 8181, 8829, 9801, 9963, 8829, 4212,
            9396, 8424, 7695, 7938, 4131, 8424, 3969, 8910, 8100, 7695,
            8019, 3969, 9072, 8424, 4131, 9234, 7695, 4131, 8019, 4293,
            4455, 4131, 7857, 8181, 8262, 10125
        ]
        print(decode_static(sample_nums, 81))
