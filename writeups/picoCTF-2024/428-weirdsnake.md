# Writeup: weirdSnake (Challenge ID: 428)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Python Bytecode Decompilation & Stream XOR Inversion
- **Difficulty:** Medium
- **Author:** Junias Bonou
- **Event:** picoCTF 2024
- **Points:** 300
- **Flag:** `academy{N0t_sO_coNfus1ng_sn@ke_d322ee40}`

---

## Problem Statement & Scope
Diberikan sebuah berkas teks (`snake`) yang berisi instruksi disasembli bytecode mesin virtual Python (CPython 3.11/3.12) hasil eksekusi pustaka `dis`. Pengguna ditantang memulihkan alur logika kode asli (*logic reconstruction*) tanpa berkas sumber `.py` asli guna mengekstrak pesan rahasia yang dienkripsi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Arsitektur Stack Machine CPython:** Mesin virtual CPython beroperasi sebagai stack machine berbasis pointer evaluasi:
   - `LOAD_CONST` / `LOAD_NAME`: Mendorong referensi objek ke puncak stack.
   - `BINARY_OP`: Mengambil dua operan dari stack, menjalankan operasi biner (seperti penambahan `+` atau XOR bitwise `^`), dan mendorong hasilnya kembali.
   - `STORE_NAME` / `STORE_FAST`: Mengambil nilai teratas stack dan menyimpannya ke namespace lokal atau modul.
2. **Deobfuskasi Rekonstruksi String Kunci:**
   - Instruksi baris 2 s.d. 6 membangun string `key_str`:
     1. `LOAD_CONST 'J'` $\rightarrow$ `key_str = 'J'`
     2. `LOAD_CONST '_'` lalu `LOAD_NAME key_str` lalu `BINARY_OP (+)` $\rightarrow$ `key_str = '_' + 'J'` = `'_J'`
     3. `LOAD_NAME key_str` lalu `LOAD_CONST 'o'` lalu `BINARY_OP (+)` $\rightarrow$ `key_str = '_J' + 'o'` = `'_Jo'`
     4. `LOAD_NAME key_str` lalu `LOAD_CONST '3'` lalu `BINARY_OP (+)` $\rightarrow$ `key_str = '_Jo' + '3'` = `'_Jo3'`
     5. `LOAD_CONST 't'` lalu `LOAD_NAME key_str` lalu `BINARY_OP (+)` $\rightarrow$ `key_str = 't' + '_Jo3'` = `'t_Jo3'`
3. **Ekspansi Kunci & Dekripsi Simetris XOR:**
   - Bytecode baris 9 mengonversi karakter kunci menjadi daftar kode ASCII integer: `key_list = [ord(c) for c in key_str]`.
   - Baris 11 s.d. 12 menggandakan panjang daftar kunci melalui `while len(key_list) < len(input_list): key_list.extend(key_list)`.
   - Baris 15 menerapkan operasi bitwise XOR satu per satu antara ciphertext `input_list` dan keystream `key_list`: $\text{result}_i = \text{input}_i \oplus \text{key}_i$.
   - Sifat involutif XOR ($A \oplus B = C \iff C \oplus B = A$) memungkinkan rekonstruksi plaintext murni tanpa membutuhkan kunci privat asimetris.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Ekstraksi array ciphertext dari baris 1 disasembli bytecode:
   ```python
   input_list = [21, 60, 43, 11, 86, 25, 38, 49, 33, 3, 0, 0, 57, 32, 108, 23, 48, 4, 9, 70, 7, 110, 36, 8, 108, 7, 49, 10, 4, 86, 43, 59, 121, 93, 1, 17, 58, 126, 95, 78]
   ```
2. Rekonstruksi kunci pengacak:
   ```python
   key_str = "t_Jo3"
   key_list = [ord(c) for c in key_str]
   while len(key_list) < len(input_list):
       key_list.extend(key_list)
   ```
3. Hitung byte hasil dekripsi dan ubah ke representasi string ASCII:
   ```python
   result = [a ^ b for a, b in zip(input_list, key_list)]
   flag = "".join(map(chr, result))
   # academy{N0t_sO_coNfus1ng_sn@ke_d322ee40}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{N0t_sO_coNfus1ng_sn@ke_d322ee40}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 428, "flag": "academy{N0t_sO_coNfus1ng_sn@ke_d322ee40}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pemahaman Bytecode Interpreter Python:** Dalam investigasi forensik insiden keamanan siber dan analisis malware LKS, pelaku ancaman kerap mendistribusikan muatan berbahaya dalam bentuk file `.pyc` terkompilasi atau skrip terobfuskasi. Kemampuan membaca opcodes `dis` secara langsung tanpa dekompiler otomatis (seperti `uncompyle6` atau `decompyle++` yang sering macet pada Python versi 3.11+) menjadi keunggulan kompetitif mutlak.
- **Kelemahan Stream Cipher Kunci Pendek Berulang:** Menggunakan pengulangan kunci XOR pendek (`key_list.extend(key_list)`) sangat rentan terhadap analisis frekuensi indeks Kasiski dan analisis statistik. Selalu gunakan algoritma enkripsi terotentikasi (Authenticated Encryption) seperti AES-256-GCM atau ChaCha20-Poly1305 dengan Nonce unik pada setiap sesi.
