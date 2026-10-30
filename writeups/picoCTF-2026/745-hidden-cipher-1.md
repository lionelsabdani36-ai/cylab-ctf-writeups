# 745 - Hidden Cipher 1 (Reverse Engineering, picoCTF 2026, Medium)

## Challenge Metadata
- ID: 745 | Event: picoCTF 2026 | Author: Yahya Meddy
- Category: Reverse Engineering | Difficulty: Medium (2)
- Flag: `academy{xor_unpack_4nalys1s_f3d3a874}`

## Problem Statement & Scope
Lab on-demand: biner `hiddencipher` (UPX-packed) + `flag.txt` berisi
`academy{fake_flag}` (placeholder lokal). Instance live mencetak
ciphertext hex per-instance via netcat. Tugas: pulihkan flag asli.

## Teori & Akar Kerentanan (Root Cause)
1. UPX packing hanya obfuscation lapisan transport, bukan enkripsi:
   `upx -d` memulihkan ELF utuh (hint 1 valid).
2. Kunci hardcoded: `get_secret` menulis literal `S3Cr3t` (6 byte) ke .bss.
   Kunci di dalam biner = bukan rahasia (CWE-798).
3. Cipher XOR repeating-key bersifat involusi: `P ^ K ^ K = P`, sehingga
   siapa pun yang mengekstrak kunci (6 byte dari disassembly `12a9`)
   dapat mendekripsi seluruh flag (hint 3).
4. Loop memakai pembagian unsigned via magic `imul 0x2aaaaaab`
   (kompilasi `i / 6`), lalu `i - 6*(i/6)` = `i % 6` sebagai indeks kunci.

## Rekonstruksi Eksploitasi Step-by-Step
1. Download `hiddencipher.zip` dari CDN challenge-files.
2. `upx -d hiddencipher -o hc_unpacked` (7056 -> 16496 bytes).
3. `objdump -d -M intel hc_unpacked`: di `get_secret` terlihat 6 store
   byte `0x53 0x33 0x43 0x72 0x33 0x74` = `S3Cr3t`.
4. Di `main`, loop `fread` flag lalu `xor flag[i], key[i % 6]`,
   cetak `%02x` per byte.
5. Launch instance (`PUT /api/challenges/745/instance/`), tunggu RUNNING,
   baca ciphertext dari `nc chatelaine.cylabacademy.net 22038`:
   `3250221656192a483b1d412b265d3313501f0c072d135f0d2002302d55473700224a04402e`.
6. Dekripsi: `bytes(c ^ b"S3Cr3t"[i%6])` -> flag di atas.
7. Submit `POST /api/submissions/` -> `correct: true`; `DELETE` instance.

## Flag & Verifikasi
- `academy{xor_unpack_4nalys1s_f3d3a874}` (`correct: true`, historical false).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Jangan hardcode kunci di biner; ambil dari KMS/env dengan ACL ketat.
- UPX bukan proteksi: strip + pack hanya menunda analis amatir.
- Defensif: kunci per-instance dari secret manager, enkripsi terotentikasi
  (AES-GCM), dan pastikan placeholder `flag.txt` tidak ikut terdistribusi.
