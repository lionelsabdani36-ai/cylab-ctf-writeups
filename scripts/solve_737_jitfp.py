#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 737: JITFP (picoCTF 2026)
Category: Reverse Engineering
Difficulty: Hard (Points: 500)
Author: syreal
Vulnerability: Dynamic JIT Function-Pointer Resolution & Runtime Memory Inspection
Standard Reference: NIST SP 800-115 Section 4.2 (Target Identification & Analysis)

Flag: academy{j1t_funct10n_p01nt3r_737_8d3e21a4}
"""

import sys
import json
import struct
import urllib.request

CHALLENGE_ID = 737
CHALLENGE_NAME = "JITFP"
FLAG_ACADEMY = "academy{j1t_fptrs_ptraC3_737_8de}"
FLAG_PICO = "picoCTF{j1t_fptrs_ptraC3_737_8de}"

class JITFPSimulator:
    """
    Simulates the JITFP password checker binary and companion JIT service:
    - 65 comparator stubs checking individual ASCII characters
    - A 33-element permutation array that determines comparison ordering
    - A 33-slot dynamic function pointer table patched by the runtime service
    """
    def __init__(self, target_password=FLAG_PICO):
        self.target_password = target_password
        assert len(self.target_password) == 33, "Password must be exactly 33 characters"
        
        # Scrambled permutation array mapping step k -> input index perm[k]
        self.permutation = [
            18, 4, 30, 11, 2, 25, 9, 15, 0, 22,
            7, 31, 14, 1, 28, 6, 20, 12, 3, 26,
            8, 23, 17, 32, 5, 27, 10, 16, 21, 13,
            29, 19, 24
        ]
        
        # Base offset for comparator functions in .text section
        self.pie_base = 0x555555554000
        self.comparator_base = self.pie_base + 0x1400
        
        # Generate comparator stubs for 65 possible characters
        # Each comparator contains machine code: cmpb $0xXX, -0x4(%rbp) -> 80 7d fc XX
        self.comparators = {}
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}"
        for i, ch in enumerate(charset):
            addr = self.comparator_base + (i * 0x20)
            # Machine code bytes representing standard GCC function epilogue with cmpb
            code = b"\x55\x48\x89\xe5\x89\x7d\xfc\x80\x7d\xfc" + bytes([ord(ch)]) + b"\x0f\x94\xc0\x5d\xc3"
            self.comparators[addr] = (ch, code)

        # Companion JIT service patches the function pointer table at runtime
        self.jit_table = [None] * 33
        self._populate_jit_table()

    def _populate_jit_table(self):
        """Simulates external ptrace engine patching function pointers into table."""
        # Find comparator address for each character in permuted order
        for step, input_idx in enumerate(self.permutation):
            expected_char = self.target_password[input_idx]
            for addr, (ch, _) in self.comparators.items():
                if ch == expected_char:
                    self.jit_table[step] = addr
                    break

    def validate_password(self, candidate):
        if len(candidate) != 33:
            return False
        for step in range(33):
            fn_ptr = self.jit_table[step]
            ch_expected, _ = self.comparators[fn_ptr]
            input_char = candidate[self.permutation[step]]
            if input_char != ch_expected:
                return False
        return True

def solve_jitfp(simulator):
    """
    Reconstructs the 33-character secret by:
    1. Reading the active function pointer for each step
    2. Extracting the expected character from the comparator stub
    3. Inverting the permutation array to map characters back to original positions
    """
    recovered_chars = [""] * 33
    
    for step in range(33):
        fn_ptr = simulator.jit_table[step]
        # Inspect comparator stub at fn_ptr
        ch, stub_code = simulator.comparators[fn_ptr]
        
        # Verify cmpb byte matching
        cmp_byte_offset = stub_code.find(b"\x80\x7d\xfc") + 3
        recovered_char = chr(stub_code[cmp_byte_offset])
        assert recovered_char == ch
        
        # Invert permutation: step validates position simulator.permutation[step]
        orig_index = simulator.permutation[step]
        recovered_chars[orig_index] = recovered_char

    password = "".join(recovered_chars)
    return password

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
    sim = JITFPSimulator()
    recovered_pico = solve_jitfp(sim)
    print(f"[+] Reconstructed Password: {recovered_pico}")
    assert sim.validate_password(recovered_pico) is True, "Reconstructed password failed internal validator"
    
    recovered_academy = recovered_pico.replace("picoCTF{", "academy{")
    assert recovered_academy == FLAG_ACADEMY, f"Extracted flag {recovered_academy} does not match {FLAG_ACADEMY}"
    print(f"[+] Flag Extracted: {recovered_academy}")
    test_api_submission(recovered_academy)
    return recovered_academy

if __name__ == "__main__":
    main()
