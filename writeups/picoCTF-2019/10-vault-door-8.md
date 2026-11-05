# Writeup: vault-door-8 (Challenge ID: 10)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Bit Permutation & Inversion
- **Difficulty:** Medium
- **Author:** Mark E. Haase
- **Event:** picoCTF 2019
- **Points:** 450
- **Flag:** `academy{s0m3_m0r3_b1t_sh1fTiNg_14c0f2f11}`

---

## Problem Statement & Scope
Diberikan berkas sumber Java `VaultDoor8.java` dengan gaya penulisan kode yang sengaja dibuat padat (minified/obfuscated). Program menerima kata sandi 32 karakter dan menjalankan metode `scramble()`, yang melakukan serangkaian transposisi posisi bit (bit permutation/swapping) pada setiap karakter sebelum membandingkannya dengan array byte acak `expected`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Sifat Involutif Operasi Swap (Bit Transposition as Involutions):**
   - Fungsi `switchBits(char c, int p1, int p2)` menukar nilai bit pada posisi indeks `p1` dan `p2`.
   - Secara matematis, operasi transposisi dua elemen bersifat involutif ($T_{(p_1, p_2)} \circ T_{(p_1, p_2)} = I$, di mana $I$ adalah fungsi identitas).
   - Sebuah rantai transposisi berurutan $T = T_k \circ \dots \circ T_2 \circ T_1$ memiliki invers tepat berupa rantai operasi dalam urutan terbalik:
     $$T^{-1} = T_1 \circ T_2 \circ \dots \circ T_k$$
2. **Kelemahan Permutasi Tanpa Difusi Kriptografis (SP-Network Incompleteness):**
   - Transposisi hanya mengubah posisi bit dalam lingkup 1 byte secara independen per karakter tanpa difusi antar-byte atau penambahan non-linear S-box yang tidak dapat dibalik.
   - Karena setiap operasi reversibel dan tanpa kunci rahasia (zero secret key), enkripsi yang diterapkan hanyalah bentuk obfuskasi data dasar (CWE-327 / Use of a Broken or Risky Cryptographic Algorithm).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis urutan penukaran bit forward pada metode `scramble()`:
   - Langkah 1: `switchBits(c, 1, 2)`
   - Langkah 2: `switchBits(c, 0, 3)`
   - Langkah 3: `switchBits(c, 5, 6)`
   - Langkah 4: `switchBits(c, 4, 7)`
   - Langkah 5: `switchBits(c, 0, 1)`
   - Langkah 6: `switchBits(c, 3, 4)`
   - Langkah 7: `switchBits(c, 2, 5)`
   - Langkah 8: `switchBits(c, 6, 7)`
2. Susun fungsi invers `unscramble()` dengan membalik urutan eksekusi secara simetris:
   - Langkah 1: `switchBits(c, 6, 7)`
   - Langkah 2: `switchBits(c, 2, 5)`
   - Langkah 3: `switchBits(c, 3, 4)`
   - Langkah 4: `switchBits(c, 0, 1)`
   - Langkah 5: `switchBits(c, 4, 7)`
   - Langkah 6: `switchBits(c, 5, 6)`
   - Langkah 7: `switchBits(c, 0, 3)`
   - Langkah 8: `switchBits(c, 1, 2)`
3. Terapkan fungsi pembalik pada 32 byte array `expected`:
   - `0xF4, 0xC0, 0x97, 0xF0, 0x77, 0x97, 0xC0, 0xE4, ...`
   - Hasil unscramble menghasilkan karakter: `s0m3_m0r3_b1t_sh1fTiNg_14c0f2f11`
4. Format flag resmi: `academy{s0m3_m0r3_b1t_sh1fTiNg_14c0f2f11}`.
5. Eksekusi solver Python:
   ```bash
   python3 scripts/solve_10_vault_door_8.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{s0m3_m0r3_b1t_sh1fTiNg_14c0f2f11}`
- **Verifikasi:** POST `/api/submissions/` merespons `{"correct": true}` (HTTP Status 201 Created).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Takeaway LKS:** Penguji keamanan siber harus mengenali konsep permutasi aljabar dan sifat simetri operasi bitwise. Obfuskasi gaya kode minified tidak memberikan perlindungan keamanan nyata (Security through Obscurity) terhadap analisis statis.
- **Mitigasi Defensif:** Validasi integritas otentikasi harus menggunakan arsitektur verifikasi cryptographic hashing (SHA-256 / SHA-3) atau standar verifikasi password RFC 8018 / NIST SP 800-63B, bukan logika transformasi bit buatan sendiri (custom cipher).
