# Writeup: Bbbbloat (Challenge ID: 255)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Binary Deobfuscation & Dead-Code Elimination
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{cu7_7h3_bl047_1cf3a481}`

---

## Problem Statement & Scope

Diberikan sebuah berkas biner ELF 64-bit stripped bernama `bbbbloat` yang dapat diunduh dari pustaka pustaka berkas CyLab:
`https://challenge-files.cylabacademy.net/library/e4f53b5263b966ad335fed2c42a9bf41c69b5cbc39c0a30a094e2f267e1a27e0/bbbbloat`

Ketika program dijalankan, konsol menampilkan permintaan masukan pengguna:
`What's my favorite number?`
Jika pengguna memasukkan bilangan yang salah, program mencetak pesan kegagalan dan berhenti (`exit(0)`).
Jika pengguna memasukkan bilangan yang tepat, program mendekode dan mencetak bendera rahasia.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Penyisipan Kode Mati / Aritmetika Bloat (CWE-1164 / CWE-514 / NIST SP 800-115 § 4.2):**
   - Pembuat tantangan menerapkan teknik obfuskasi berbasis *dead-code insertion*.
   - Di antara instruksi-instruksi kritis pada fungsi `main()`, disisipkan blok-blok operasi aritmetika berulang:
     ```assembly
     mov    DWORD PTR [rbp-0x3c], 0x3078
     add    DWORD PTR [rbp-0x3c], 0x13c29e
     sub    DWORD PTR [rbp-0x3c], 0x30a8
     shl    DWORD PTR [rbp-0x3c], 1
     imul   rdx, rdx, 0x55555556
     ...
     ```
   - Operasi ini memanipulasi slot stack `[rbp-0x3c]`, namun nilainya tidak pernah dibaca oleh logika percabangan utama maupun fungsi pencetakan. Tujuan dari kode kembung (*bloat*) ini murni untuk membingungkan analis dan mengelabui mesin dekompilasi otomatis (Ghidra/IDA Pro).

2. **Kredensial Hardcoded pada Berkas Biner Klien (CWE-798 / CWE-200):**
   - Meskipun berkas biner di-strip (seluruh tabel simbol dan informasi debugging dihapus), logika verifikasi tetap bergantung pada konstanta statis:
     ```assembly
     14c8:  mov    eax, DWORD PTR [rbp-0x40]
     14cb:  cmp    eax, 0x86187
     14d0:  jne    1581 <fail_branch>
     ```
   - Nilai heksadesimal `0x86187` setara dengan bilangan desimal `549255`.
   - String bendera terobfuskasi disematkan langsung ke dalam slot stack `[rbp-0x30]` melalui 4 buah immediate quadword:
     - Quadword 1: `0x4C4A3E3635323432` -> `b"24256>JL"`
     - Quadword 2: `0x3062396630664634` -> `b"4Ff0f9b0"`
     - Quadword 3: `0x34603066635F3D33` -> `b"3=_cf0`4"`
     - Quadword 4: `0x004E606763326237` -> `b"7b2cg`N\x00"`

3. **Subrutin Dekripsi Simetris ROT47 (CWE-327):**
   - Subrutin pada offset `0x1249` mengimplementasikan transformasi byte reversibel:
     Untuk setiap karakter `c` pada rentang ASCII `0x20 < c` dan `c != 0x7f`:
     `v = c + 0x2f` (tambah 47 desimal).
     Jika `v > 0x7e` (melebihi karakter `~` / 126 desimal), maka `v = v - 0x5e` (kurang 94 desimal).
   - Ini merupakan implementasi kanonikal dari algoritma ROT47 (permutasi involutif pada 94 karakter ASCII yang dapat dicetak).
   - Karena algoritma bersifat simetris dan data tersimpan lengkap di sisi klien, analisis statis memungkinkan ekstraksi bendera secara deterministik tanpa memerlukan eksekusi dinamis berkas biner.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh berkas biner `bbbbloat`:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/e4f53b5263b966ad335fed2c42a9bf41c69b5cbc39c0a30a094e2f267e1a27e0/bbbbloat
   ```
2. Lakukan disassembli statis menggunakan `objdump`:
   ```bash
   objdump -d -M intel bbbbloat > bbbbloat.asm
   ```
3. Cari instruksi perbandingan nilai masukan:
   ```bash
   grep -B 5 -A 5 "cmp.*eax" bbbbloat.asm
   ```
   Ditemukan perbandingan `cmp eax, 0x86187`. Konversi nilai ke desimal:
   `0x86187 = 549255`.
4. Identifikasi pemuatan 4 quadword stack string pada alamat `0x1329` hingga `0x135d`:
   - Rangkai byte little-endian menghasilkan string terobfuskasi:
     `24256>JL4Ff0f9b03=_cf0`47b2cg`N`
5. Terapkan transformasi ROT47 pada setiap karakter:
   - Karakter `'2'` (50) + 47 = 97 -> `'a'`
   - Karakter `'4'` (52) + 47 = 99 -> `'c'`
   - Karakter `'2'` (50) + 47 = 97 -> `'a'`
   - Karakter `'5'` (53) + 47 = 100 -> `'d'`
   - Karakter `'6'` (54) + 47 = 101 -> `'e'`
   - Karakter `'>'` (62) + 47 = 109 -> `'m'`
   - Karakter `'J'` (74) + 47 = 121 -> `'y'`
   - Karakter `'L'` (76) + 47 = 123 -> `'{'`
   - Hasil lengkap mendekode menjadi `academy{cu7_7h3_bl047_1cf3a481}`.
6. Eksekusi skrip solver mandiri `scripts/solve_255_bbbbloat.py`:
   ```bash
   python3 scripts/solve_255_bbbbloat.py
   ```
   Output:
   ```text
   [*] Auditing Module 255: Bbbbloat
   [*] Stage 1: Static Parameter Resolution -> Favorite Number: 549255 (0x86187)
   [*] Stage 2: Unpacking 31-byte stack blob: 24256>JL4Ff0f9b03=_cf0`47b2cg`N
       [+] Decoded Flag: academy{cu7_7h3_bl047_1cf3a481}
   [+] Output Flag: academy{cu7_7h3_bl047_1cf3a481}
   ```
7. Verifikasi penyerahan bendera ke REST API CyLab (`POST /api/submissions/`). Respons: `HTTP 201 Created` dengan status `correct: true`.

---

## Flag & Verifikasi

- **Platform Verified Flag:** `academy{cu7_7h3_bl047_1cf3a481}`
- **Matriks Wrapper Acceptance:**
  - `academy{cu7_7h3_bl047_1cf3a481}`: **ACCEPTED (HTTP 201 Created, correct: true)**
  - `picoCTF{cu7_7h3_bl047_1cf3a481}`: **REJECTED (HTTP 201 Created, correct: false)**
- **Audit Bukti HTTP Live:**
  ```json
  {
    "user": 1072359,
    "challenge": 255,
    "flag": "academy{cu7_7h3_bl047_1cf3a481}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi Rekayasa Balik LKS Cyber Security:**
   - Kemampuan membaca instruksi rakitan x86-64 pada biner stripped (*Position Independent Executable* / PIE).
   - Membedakan instruksi fungsional dari instruksi kode mati (*dead code / dead stores*) melalui analisis def-use chain.
   - Merekonstruksi susunan data little-endian dari register 64-bit pada stack frame biner.
2. **Mitigasi Defensif & Hardening Arsitektur Perangkat Lunak:**
   - *Security through Obscurity is NOT Security:* Menghapus simbol (strip) dan menyisipkan instruksi bloat hanya memperlambat analisis sesaat, namun tidak mencegah ekstraksi rahasia.
   - Jangan pernah mempercayai klien (*Zero Trust Client Architecture*): Verifikasi kata sandi, token otentikasi, dan dekripsi data penting harus dieksekusi di lingkungan server yang terlindungi.
   - Apabila aplikasi harus mendistribusikan data sensitif ke perangkat pengguna, gunakan enkripsi asimetris dengan validasi sertifikat atau remote attestation berbasis perangkat keras (TPM / Secure Enclave).
