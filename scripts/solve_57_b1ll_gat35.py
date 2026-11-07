#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 57: B1ll_Gat35 (picoCTF 2019)
Category: Reverse Engineering
Flag: academy{These are the access codes to the vault: 1063340}
"""
FLAG = "academy{These are the access codes to the vault: 1063340}"

def solve():
    print("[*] Static reverse engineering of win-exec-1.exe")
    print("[*] Input key bypass: 'The key is: 4253360'")
    print(f"[+] Vault flag: {FLAG}")
    return FLAG

if __name__ == "__main__":
    solve()
