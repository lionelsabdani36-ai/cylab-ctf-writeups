# Writeup: vault-door-6 (Challenge ID: 45)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Single-Byte XOR Inversion
- **Difficulty:** Medium
- **Author:** Mark E. Haase
- **Event:** picoCTF 2019
- **Points:** 350
- **Flag:** `academy{n0t_mUcH_h4rD3r_tH4n_x0r_cfee664}`

---

## Problem Statement & Scope
Diberikan program Java `VaultDoor6.java`. Logika pengecekan kata sandi menerapkan operasi bitwise XOR pada setiap byte input pengguna dengan konstanta `0x55` dan memverifikasi hasilnya terhadap array byte acak `myBytes` berukuran 32 elemen. Peserta diminta membalikkan operasi tersebut untuk merekonstruksi kata sandi asli.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Sifat Involutif Operasi XOR (Exclusive-OR):** Operasi bitwise XOR ($\oplus$) memiliki sifat self-inverting (involusi):
   $$A \oplus B = C \iff C \oplus B = A$$
   Karena setiap byte input $P_i$ dievaluasi dengan:
   $$(P_i \oplus 0x55) - M_i = 0 \implies P_i \oplus 0x55 = M_i$$
   Maka teks terang dapat diperoleh secara deterministik melalui:
   $$P_i = M_i \oplus 0x55$$
2. **Kelemahan Static Key XOR:** Menggunakan kunci konstan 1-byte (`0x55`) pada seluruh aliran pesan memusnahkan keragaman entropi dan dapat dipecahkan dalam $O(1)$ untuk setiap byte target.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Ekstrak 32 nilai heksadesimal dari array `myBytes`:
   ```java
   0x3b, 0x65, 0x21, 0xa , 0x38, 0x0 , 0x36, 0x1d,
   0xa , 0x3d, 0x61, 0x27, 0x11, 0x66, 0x27, 0xa ,
   0x21, 0x1d, 0x61, 0x3b, 0xa , 0x2d, 0x65, 0x27,
   0xa , 0x36, 0x33, 0x30, 0x30, 0x63, 0x63, 0x61
   ```
2. Lakukan operasi XOR setiap elemen dengan nilai kunci `0x55` (85 desimal):
   - $0x3b \oplus 0x55 = 0x6e$ (`'n'`)
   - $0x65 \oplus 0x55 = 0x30$ (`'0'`)
   - $0x21 \oplus 0x55 = 0x74$ (`'t'`)
   - ... dan seterusnya untuk seluruh 32 karakter.
3. String kata sandi yang dihasilkan:
   `n0t_mUcH_h4rD3r_tH4n_x0r_cfee664`
4. Format flag resmi: `academy{n0t_mUcH_h4rD3r_tH4n_x0r_cfee664}`.
5. Eksekusi solver Python:
   ```bash
   python3 scripts/solve_45_vault_door_6.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{n0t_mUcH_h4rD3r_tH4n_x0r_cfee664}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Kelemahan Operasi XOR Tunggal:** Seringkali pengembang pemula mengimplementasikan XOR encoding dengan konstanta tetap sebagai skema enkripsi internal. Skema ini sangat rentan terhadap *known-plaintext attack* dan *key recovery* instan.
- **Standar Stream Cipher Modern:** Jika arsitektur memerlukan enkripsi berbasis XOR stream berkecepatan tinggi, gunakan algoritma modern terstandardisasi IETF seperti ChaCha20 yang memadukan permutasi non-linear ARX (Add-Rotate-Xor) dengan ruang kunci 256-bit dan nonce unik.
