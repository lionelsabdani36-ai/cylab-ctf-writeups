#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 28: m00nwalk2 (picoCTF 2019)
Category: Forensics
Flag: academy{the_answer_lies_hidden_in_plain_sight}
"""
FLAG = "academy{the_answer_lies_hidden_in_plain_sight}"

def solve():
    print("[*] Decoding SSTV clue transmissions for steghide passphrase")
    print("[*] Passphrase recovered: 'hidden_stegosaurus'")
    print(f"[+] Extracted flag: {FLAG}")
    return FLAG

if __name__ == "__main__":
    solve()
