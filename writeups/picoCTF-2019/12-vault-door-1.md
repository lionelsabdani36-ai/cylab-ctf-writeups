# Writeup: vault-door-1 (Challenge ID: 12)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Source Code Analysis
- **Difficulty:** Medium
- **Author:** Mark E. Haase
- **Event:** picoCTF 2019
- **Points:** 100
- **Flag:** `academy{d35cr4mbl3_tH3_cH4r4cT3r5_179fbd}`

---

## Problem Statement & Scope
Disediakan berkas source code Java `VaultDoor1.java`. Logika validasi kata sandi brankas memeriksa setiap karakter string input pada indeks tertentu terhadap konstanta karakter acak. Peserta diminta membalikkan permutasi posisi karakter tersebut untuk merekonstruksi kata sandi lengkap.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pemeriksaan Karakter Per Karakter (Scatter-Match Pattern):** Fungsi `checkPassword` melakukan perbandingan individual menggunakan ekspresi `password.charAt(index) == 'char'`. Seluruh kondisi dihubungkan dengan operator logika AND (`&&`).
2. **Ketiadaan Hash Komputasi:** Menguji password secara langsung (cleartext comparison) tanpa menggunakan cryptographic hash function berkunci (seperti Argon2, bcrypt, atau PBKDF2) merupakan kerentanan fatal arsitektur autentikasi.
3. **Deterministik Array Indexing:** Karena seluruh indeks dari 0 hingga 31 dievaluasi secara statis, penyerang cukup memetakan kembali pasangan `(indeks, karakter)` ke dalam array terurut berukuran 32.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis potongan kode `VaultDoor1.java`:
   ```java
   password.charAt(0)  == 'd' &&
   password.charAt(29) == '9' &&
   password.charAt(4)  == 'r' &&
   ...
   ```
2. Parsing seluruh kondisi menggunakan ekspresi reguler (Regex) untuk mengekstrak pasangan indeks numerik dan karakter.
3. Tempatkan setiap karakter pada slot array target sesuai indeksnya.
4. Gabungkan 32 karakter menjadi string kata sandi utuh:
   `d35cr4mbl3_tH3_cH4r4cT3r5_179fbd`
5. Format ke dalam flag resmi: `academy{d35cr4mbl3_tH3_cH4r4cT3r5_179fbd}`.
6. Eksekusi skrip otomasi:
   ```bash
   python3 scripts/solve_12_vault_door_1.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{d35cr4mbl3_tH3_cH4r4cT3r5_179fbd}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Otentikasi Berbasis Hash (Secure Credential Storage):** Jangan pernah memverifikasi kredensial melalui perbandingan string telanjang di kode sumber. Simpan representasi salted hash dari password dan gunakan verifikasi waktu-konstan (`MessageDigest.isEqual`) untuk mencegah *timing attacks*.
- **Obfuscation Bukan Pengganti Keamanan:** Menyebarkan posisi karakter tidak memberikan perlindungan kriptografis terhadap analisis statis dasar.
