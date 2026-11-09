#!/usr/bin/env python3
"""
CyLab Security Academy Learning Path Verifier: Module 62 (Playlist 6: Investigation Encoded Series)
Challenge: investigation_encoded_1 (ID 47) | Kategori: Forensics/Reverse Engineering | Difficulty: Hard (3)
Standar: NIST SP 800-115 Section 4.3 (Digital Forensics & Cryptographic Analysis)

Mekanika (audit batch 181, 2026-11-09):
1. Biner `investigation-encoded-1-mystery` (ELF 64-bit PIE, tidak di-strip) memuat:
   - `secret`  : 37 byte (0x25) pada .rodata vaddr 0x2020 (pool bit Huffman).
   - `matrix`  : 27 entri pasangan int32 (len, start) pada .rodata vaddr 0x2060
                 (26 huruf a-z + index 26 untuk spasi ' ' yang dipetakan ke '{').
2. `encode()` memproses flag.txt per karakter: lower() -> isValid() -> idx = ord(c)-'a'
   -> bit [start, start+len) diekstrak MSB-first dari `secret` -> dikemas ke bitstream.
3. Decoder invers: greedy prefix parsing (kode bebas-prefiks / canonical Huffman).

HASIL VERIFIKASI LIVE (POST /api/submissions/, X-CSRFToken, HTTP 201):
   - `academy{encodedxxkpbxrzrn}` -> correct: false   (format wrapper DITOLAK; lihat NOTE deskripsi lab)
   - `encodedxxkpbxrzrn`          -> correct: true    (format RAW = format resmi challenge 47 saat ini)
   Platform men-rekey format flag per challenge; deskripsi lab menyatakan
   "NOTE: The flag is not in the normal academy{XXX} format."

Pemakaian:
   python3 verify_module_62_investigation_encoded_1.py <path-biner-mystery> <path-file-output>
   (mode offline: rekonstruksi kodebook + dekode; tanpa argumen: self-test artefak ter-cache)
"""

import struct
import sys
import os

SECRET_OFF = 0x2020   # vaddr == file offset pada segmen bawah PIE ini
MATRIX_OFF = 0x2060
SECRET_LEN = 0x25
MATRIX_LEN = 0xD8
EXPECTED_TOKEN = "encodedxxkpbxrzrn"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
CHALLENGE_ID = 47
MODULE_ID = 62
PLAYLIST_ID = 6


def extract_codebook(binary: bytes) -> dict:
    """Rekonstruksi kamus kode prefiks kustom langsung dari .rodata biner (tanpa eksekusi)."""
    secret = binary[SECRET_OFF:SECRET_OFF + SECRET_LEN]
    matrix = binary[MATRIX_OFF:MATRIX_OFF + MATRIX_LEN]
    pairs = struct.unpack("<%di" % (len(matrix) // 4), matrix)
    codebook = {}
    for i in range(len(pairs) // 2):
        ln, start = pairs[2 * i], pairs[2 * i + 1]
        bits = "".join(
            str((secret[(start + k) >> 3] >> (7 - ((start + k) & 7))) & 1)
            for k in range(ln)
        )
        ch = chr(ord("a") + i) if i < 26 else "{"
        codebook[bits] = ch
    return codebook


def decode_bitstream(raw: bytes, codebook: dict) -> str:
    """Greedy prefix parsing atas bitstream MSB-first (properti bebas-prefiks)."""
    bits = "".join(format(b, "08b") for b in raw)
    out, buf = [], ""
    for b in bits:
        buf += b
        if buf in codebook:
            out.append(codebook[buf])
            buf = ""
    return "".join(out).rstrip("{")  # bit padding '00' sisa flush dapat match kode '{'


def main(argv):
    if len(argv) >= 3:
        binary = open(argv[1], "rb").read()
        raw = open(argv[2], "rb").read()
    else:
        cache = os.path.expanduser("~/.hermes/cache/scratch")
        binary = open(os.path.join(cache, "ie1-mystery"), "rb").read()
        raw = open(os.path.join(cache, "ie1-output"), "rb").read()
    codebook = extract_codebook(binary)
    assert len(codebook) == 27, "kodebook harus memuat 27 entri (a-z + '{')"
    token = decode_bitstream(raw, codebook)
    print(f"[+] Modul {MODULE_ID} (Playlist {PLAYLIST_ID}) / Challenge {CHALLENGE_ID}")
    print(f"[+] Kodebook terekstraksi: {len(codebook)} entri (len {min(len(k) for k in codebook)}"
          f"-{max(len(k) for k in codebook)} bit, bebas-prefiks)")
    print(f"[+] Token terdekode: {token!r}")
    assert token == EXPECTED_TOKEN, f"MISMATCH: {token!r} != {EXPECTED_TOKEN!r}"
    print("[+] PASS: token cocok dengan flag terverifikasi live (correct: true, HTTP 201)")
    print(f"[+] Format resmi platform saat ini: RAW (tanpa wrapper academy{{}})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
