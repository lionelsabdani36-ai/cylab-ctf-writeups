# Writeup: hashcrack (Challenge ID: 475)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Hash Algorithm Identification & Dictionary Password Cracking
- **Difficulty:** Easy
- **Author:** picoCTF Team
- **Event:** picoCTF 2025
- **Points:** 100
- **Flag:** `academy{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}`

---

## Problem Statement & Scope
Sebuah server perusahaan mengalami insiden kebocoran data akibat penggunaan algoritma hash kata sandi yang lemah oleh administrator. Layanan autentikasi menantang pengguna untuk memecahkan tiga tingkat hash berurutan (MD5, SHA-1, dan SHA-256) untuk membuktikan kelemahan kata sandi yang digunakan dan memperoleh flag rahasia.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Identifikasi Fungsi Hash Berdasarkan Panjang Digest:**
   Format hash standar heksadesimal memiliki panjang representasi tetap:
   - **MD5:** 128 bit = 16 byte = 32 karakter hex.
   - **SHA-1:** 160 bit = 20 byte = 40 karakter hex.
   - **SHA-256:** 256 bit = 32 byte = 64 karakter hex.
2. **Kelemahan Fast Hash Function untuk Penyimpanan Kredensial:**
   MD5, SHA-1, dan SHA-256 adalah algoritma *general-purpose cryptographic hash* yang dirancang untuk kecepatan komputasi dan integritas data, bukan untuk proteksi kata sandi. Tanpa penambahan salt kriptografis unik (*cryptographic salt*) dan fungsi peregang kunci (*key-stretching* seperti Argon2, bcrypt, atau PBKDF2), kata sandi umum yang di-hash dengan algoritma ini rentan terhadap serangan kamus (*dictionary attack*) dan tabel pelangi (*rainbow tables*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Luncurkan instance lab container:
   `PUT /api/challenges/475/instance/`
2. Hubungkan ke server melalui socket TCP:
   ```bash
   nc chatelaine.cylabacademy.net 42998
   ```
3. **Tahap 1 — MD5 Hash:**
   - Hash: `482c811da5d5b4bc6d497ffa98491e38` (32 karakter hex).
   - Identifikasi algoritma: MD5 (`hashcat -m 0`).
   - Pencocokan kamus `rockyou.txt` menghasilkan teks asli: `password123`.
   - Masukkan `password123` ke server.
4. **Tahap 2 — SHA-1 Hash:**
   - Hash: `b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3` (40 karakter hex).
   - Identifikasi algoritma: SHA-1 (`hashcat -m 100`).
   - Pencocokan kamus menghasilkan teks asli: `letmein`.
   - Masukkan `letmein` ke server.
5. **Tahap 3 — SHA-256 Hash:**
   - Hash: `916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745` (64 karakter hex).
   - Identifikasi algoritma: SHA-256 (`hashcat -m 1400`).
   - Pencocokan kamus menghasilkan teks asli: `qwerty098`.
   - Masukkan `qwerty098` ke server.
6. Server memvalidasi seluruh kata sandi dan mencetak flag:
   ```text
   Correct! You've cracked the SHA-256 hash with a secret found. 
   The flag is: academy{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Gunakan Algoritma Password Hashing Modern:** Jangan pernah menggunakan MD5, SHA-1, atau SHA-256 mentah untuk menyimpan kredensial. Gunakan fungsi *slow-hash* yang tahan terhadap akselerasi perangkat keras GPU/ASIC seperti **Argon2id** (standar OWASP terkini) atau **bcrypt** dengan faktor kerja (*cost factor*) yang memadai.
- **Penerapan Salt Unik dan Kebijakan Kompleksitas Kata Sandi:** Wajibkan salt acak unik per pengguna untuk menggagalkan serangan tabel pelangi, serta terapkan verifikasi kata sandi terhadap daftar kata sandi bocor (*haveibeenpwned check*) saat pengguna mendaftar.
