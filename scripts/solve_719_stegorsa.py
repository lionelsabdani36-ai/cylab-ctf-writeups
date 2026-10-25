#!/usr/bin/env python3
"""
Solver for Challenge 719: StegoRSA (Cryptography)
Extracts hex-encoded RSA private key from JPEG metadata and decrypts flag.enc.
"""
import re
import subprocess

def solve(image_path='image.jpg', flag_enc_path='flag.enc'):
    with open(image_path, 'rb') as f:
        img_data = f.read()

    m = re.search(rb'(2d2d2d2d2d424547494e20[0-9a-fA-F]+)', img_data)
    assert m, 'Hex private key not found in image metadata'

    pem_key = bytes.fromhex(m.group(1).decode()).decode()
    with open('/tmp/recovered_priv.pem', 'w') as f_pem:
        f_pem.write(pem_key)

    cmd = ['openssl', 'pkeyutl', '-decrypt', '-inkey', '/tmp/recovered_priv.pem', '-in', flag_enc_path]
    flag = subprocess.check_output(cmd).decode().strip()
    return flag

if __name__ == '__main__':
    import sys
    img = sys.argv[1] if len(sys.argv) > 1 else '/tmp/ctf_batch4/719/image.jpg'
    enc = sys.argv[2] if len(sys.argv) > 2 else '/tmp/ctf_batch4/719/flag.enc'
    print('Flag:', solve(img, enc))
