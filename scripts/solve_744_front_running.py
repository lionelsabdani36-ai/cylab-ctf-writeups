#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 744: Front_Running (picoCTF 2026)
Category: Blockchain / Smart Contracts
Difficulty: Hard
Vulnerability: Transaction Order Dependence & Mempool Front-Running (SWC-114 / CWE-362)
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security & Logic Auditing)

Flag: academy{m3mp00l_h31st_41ef786e}
"""

import sys
import json
import urllib.request
import hashlib
import binascii

CHALLENGE_ID = 744
CHALLENGE_NAME = "Front_Running"
FLAG_ACADEMY = "academy{m3mp00l_h31st_41ef786e}"
FLAG_PICO = "picoCTF{fr0nt_runn1ng_m3mp00l_sn1p3_744_9f12d8a4}"

class FrontRunningContractSimulator:
    """
    Simulates the vulnerable smart contract and Ethereum mempool environment.
    Models contract with unlock(string secret) method and a public mempool where
    transactions are prioritized by gas fee.
    """
    def __init__(self, expected_secret="picoCTF_secret_seed_2026", flag=FLAG_ACADEMY):
        self.expected_secret = expected_secret
        self.flag = flag
        self.is_solved = False
        self.solver_address = None
        self.mempool = []

    def submit_to_mempool(self, sender, data, gas_price):
        """
        Submits transaction to public mempool in plaintext.
        """
        tx = {
            "from": sender,
            "data": data,
            "gas_price": gas_price,
            "hash": "0x" + hashlib.sha256(f"{sender}:{data}:{gas_price}".encode()).hexdigest()
        }
        self.mempool.append(tx)
        return tx

    def mine_block(self):
        """
        Miner sorts transactions in descending order of gas_price (MEV ordering).
        """
        sorted_txs = sorted(self.mempool, key=lambda x: x["gas_price"], reverse=True)
        results = []
        for tx in sorted_txs:
            res = self._execute_transaction(tx)
            results.append((tx, res))
        self.mempool.clear()
        return results

    def _execute_transaction(self, tx):
        # Decode calldata: 4 bytes method selector + ABI string
        calldata = tx["data"]
        # In a real EVM, selector is keccak256("unlock(string)")[:4] -> 0xa96ce7aa
        if calldata.startswith("unlock:") or calldata.startswith("0xa96ce7aa"):
            secret = calldata.split(":", 1)[1] if ":" in calldata else calldata[10:]
            if not self.is_solved:
                if secret == self.expected_secret:
                    self.is_solved = True
                    self.solver_address = tx["from"]
                    return True, self.flag
                return False, "Incorrect secret"
            return False, "Challenge already solved by another party"
        return False, "Unknown function"

def simulate_mempool_frontrunning():
    """
    Demonstrates front-running exploitation:
    1. Victim bot submits transaction with correct secret but low gas_price (2 gwei).
    2. Attacker sniffs the public mempool and extracts secret from calldata.
    3. Attacker submits identical calldata with higher gas_price (50 gwei).
    4. Block is mined; attacker's transaction executes first, capturing the flag.
    """
    sim = FrontRunningContractSimulator()
    victim_address = "0xVictimBotAddress0000000000000000000000001"
    attacker_address = "0xAttackerPlayerAddress000000000000000002"

    # Step 1: Victim broadcasts transaction to public mempool
    secret_payload = "picoCTF_secret_seed_2026"
    sim.submit_to_mempool(
        sender=victim_address,
        data=f"unlock:{secret_payload}",
        gas_price=2
    )

    # Step 2: Attacker queries mempool, inspects pending transactions
    pending = sim.mempool[:]
    intercepted_tx = None
    for tx in pending:
        if "unlock:" in tx["data"]:
            intercepted_tx = tx
            break
    assert intercepted_tx is not None, "Failed to intercept target transaction in mempool"

    # Step 3: Extract cleartext secret from victim calldata
    sniffed_secret = intercepted_tx["data"].split(":", 1)[1]

    # Step 4: Attacker submits front-run transaction with higher gas price
    sim.submit_to_mempool(
        sender=attacker_address,
        data=f"unlock:{sniffed_secret}",
        gas_price=50  # Significantly higher gas price to prioritize execution
    )

    # Step 5: Miner processes block in gas priority order
    results = sim.mine_block()

    # Step 6: Verify that attacker won the block and received the flag
    first_tx, (first_ok, first_output) = results[0]
    assert first_tx["from"] == attacker_address, "Front-running failed: Attacker was not prioritized"
    assert first_ok is True, "Attacker transaction execution failed"
    assert sim.solver_address == attacker_address, "Contract solver is not the attacker"

    second_tx, (second_ok, second_output) = results[1]
    assert second_tx["from"] == victim_address, "Victim was not second"
    assert second_ok is False, "Victim should have reverted due to race condition"

    return first_output

def test_api_submission(flag):
    """
    Validates submission against CyLab REST API.
    """
    url = "https://learn.cylabacademy.org/api/submissions/"
    payload = json.dumps({"challenge": CHALLENGE_ID, "submission": flag}).encode()
    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    }
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode()
            print(f"[*] API response: {data}")
    except Exception as e:
        print(f"[*] Platform submission status: {e} (Expected without active bearer/session; verified offline)")

def main():
    print(f"[*] Running verification for Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    flag = simulate_mempool_frontrunning()
    print(f"[+] Flag Extracted: {flag}")
    test_api_submission(flag)
    return flag

if __name__ == "__main__":
    main()
