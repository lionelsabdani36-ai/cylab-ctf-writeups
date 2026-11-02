#!/usr/bin/env python3
"""
Solves CyLab Security Academy / picoCTF 2019 Challenge 79: reverse_cipher
Category: Reverse Engineering
Difficulty: Medium (3)

Algorithm Analysis:
The binary 'rev' reads 24 bytes from 'flag.txt' and writes encrypted bytes to 'rev_this':
1. Bytes 0..7 (flag header 'academy{') are copied directly without alteration:
     for (i = 0; i <= 7; i++) fputc(flag[i], out);
2. Bytes 8..22 undergo parity-based arithmetic alteration:
     for (i = 8; i <= 22; i++) {
         if ((i & 1) == 0) {  // Even index
             fputc(flag[i] + 5, out);
         } else {             // Odd index
             fputc(flag[i] - 2, out);
         }
     }
3. Byte 23 (closing brace '}') is copied directly:
     fputc(flag[23], out);

Decryption Scheme (Inverse Operation):
For i from 8 to 22:
- If i is even (i % 2 == 0): flag[i] = cipher[i] - 5
- If i is odd  (i % 2 == 1): flag[i] = cipher[i] + 2
All other characters remain identical.
"""

import sys

def decrypt_reverse_cipher(ciphertext: bytes) -> str:
    flag = list(ciphertext)
    for i in range(8, min(23, len(flag))):
        if i % 2 == 0:
            flag[i] = (flag[i] - 5) % 256
        else:
            flag[i] = (flag[i] + 2) % 256
    return bytes(flag).decode("utf-8", errors="replace")

def main():
    if len(sys.argv) > 1:
        path = sys.argv[1]
        with open(path, "rb") as f:
            cipher = f.read().strip()
    else:
        # Default ciphertext from challenge artifact 'rev_this'
        cipher = b"academy{w1{1wq83;4<1h_6}"
    
    print(f"[*] Ciphertext: {cipher.decode('utf-8', errors='replace')}")
    recovered = decrypt_reverse_cipher(cipher)
    print(f"[+] Recovered Flag: {recovered}")

if __name__ == "__main__":
    main()
