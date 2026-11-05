# Writeup: PW Crack 1 (Challenge ID: 245)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Static Code Inspection & Hardcoded Credentials
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** Beginner picoMini 2022
- **Points:** 25
- **Flag:** `academy{545h_r1ng1ng_4a96bf39}`

---

## Problem Statement & Scope

Diberikan sebuah skrip Python bernama `level1.py` beserta berkas biner terenkripsi `level1.flag.txt.enc`. Skrip tersebut meminta pengguna memasukkan kata sandi autentikasi melalui prompt input konsol. Bila kata sandi cocok, program mendekripsi berkas cipher menggunakan operasi bitwise XOR dan menampilkan flag kepada pengguna.

Peserta ditugaskan untuk menganalisis kode sumber skrip, mengekstrak kata sandi yang valid, dan memulihkan token bendera resmi format `academy{...}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Penggunaan Kredensial Hardcoded (CWE-259 / CWE-798):**
   - Kerentanan utama pada tantangan ini adalah penulisan string kata sandi secara langsung (*hardcoded plaintext*) pada struktur percabangan logika program:
     ```python
     if (user_pw == "1e1a"):
     ```
   - Dalam arsitektur perangkat lunak yang aman, kredensial tidak boleh diletakkan di sisi klien atau dalam kode sumber terbuka karena dapat diinspeksi secara statis oleh pihak mana pun yang memiliki akses baca ke berkas.
2. **Kriptografi Simetris Berbasis Bitwise XOR (Vernam Stream Primitive):**
   - Fungsi dekripsi `str_xor(secret, key)` menerapkan operasi eksklusif-OR (`^`) per karakter antara ciphertext dengan kunci `key` yang direplikasi sepanjang teks rahasia.
   - Sifat involutori XOR: $C \oplus K = P \iff P \oplus K = C$.
   - Begitu kunci autentikasi `"1e1a"` diketahui, ciphertext `level1.flag.txt.enc` dapat didekripsi secara deterministik menjadi teks terang.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh kedua artefak tantangan dari repositori pustaka berkas CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/b3e85410c57956866b9dffa5c2abe8be9060cec09f76df39d3302aeee3d98953/level1.py
   wget https://challenge-files.cylabacademy.net/library/b3e85410c57956866b9dffa5c2abe8be9060cec09f76df39d3302aeee3d98953/level1.flag.txt.enc
   ```
2. Lakukan inspeksi statis pada `level1.py` menggunakan teks editor atau perintah `grep`:
   ```bash
   grep -n "user_pw ==" level1.py
   ```
   Ditemukan baris verifikasi autentikasi:
   ```text
   19:    if( user_pw == "1e1a"):
   ```
3. Jalankan skrip `level1.py` dan masukkan kata sandi `1e1a`:
   ```bash
   python3 level1.py
   ```
   Prompt interaktif:
   ```text
   Please enter correct password for flag: 1e1a
   Welcome back... your flag, user:
   academy{545h_r1ng1ng_4a96bf39}
   ```
4. Jalankan skrip reproduksi mandiri `scripts/solve_245_pw_crack_1.py` untuk validasi otomatis.

---

## Flag & Verifikasi

- **Flag:** `academy{545h_r1ng1ng_4a96bf39}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 245, "flag": "academy{545h_r1ng1ng_4a96bf39}", "correct": true}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemahiran *Static Code Analysis* (SAST) pada berkas skrip Python untuk modul pengujian keamanan aplikasi.
  - Pemahaman bahwa proteksi klien (*client-side validation*) tanpa mekanisme backend yang aman sama sekali tidak memberikan jaminan kerahasiaan (*zero security guarantee*).
- **Mitigasi Defensif:**
  - **Pemisahan Kredensial dari Basis Kode:** Kredensial dan rahasia aplikasi tidak boleh dimasukkan ke dalam kode sumber ataupun repositori version control.
  - **Manajemen Rahasia (NIST SP 800-57 / NIST SP 800-115):** Gunakan solusi pengelola rahasia aman (*Key Vault*, HashiCorp Vault, atau variabel lingkungan terisolasi dengan akses terbatas).
  - **Otentikasi Kriptografis Sejati:** Terapkan skema hashing kata sandi yang lambat dan resisten terhadap serangan brute-force (Argon2id atau PBKDF2) alih-alih perbandingan plaintext.
