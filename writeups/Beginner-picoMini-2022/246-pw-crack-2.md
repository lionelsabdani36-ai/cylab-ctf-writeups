# Writeup: PW Crack 2 (Challenge ID: 246)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Static Code Analysis & Hex-Encoded Hardcoded Credentials
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** Beginner picoMini 2022
- **Points:** 35
- **Flag:** `academy{tr45h_51ng1ng_ab548076}`

---

## Problem Statement & Scope

Diberikan sebuah skrip Python bernama `level2.py` dan berkas biner terenkripsi `level2.flag.txt.enc`. Berbeda dari varian sebelumnya, string kata sandi pada logika verifikasi tidak disajikan dalam bentuk string literal biasa, melainkan dikonstruksikan menggunakan fungsi konversi karakter ASCII dari nilai heksadesimal.

Peserta ditugaskan untuk merekonstruksi nilai kata sandi melalui deobfuskasi nilai heksadesimal tersebut, memasukkan kata sandi ke dalam skrip, dan mengekstrak token bendera resmi format `academy{...}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Obfuskasi Karakter ASCII Ordinal (CWE-259 / CWE-798):**
   - Kode sumber memeriksa kecocokan kata sandi dengan ekspresi berikut:
     ```python
     if (user_pw == chr(0x64) + chr(0x65) + chr(0x37) + chr(0x36)):
     ```
   - Fungsi bawaan Python `chr(i)` mengembalikan karakter teks cetak dari titik kode integer $i$.
   - Nilai literal heksadesimal:
     - `0x64` = desimal 100 = `'d'`
     - `0x65` = desimal 101 = `'e'`
     - `0x37` = desimal 55 = `'7'`
     - `0x36` = desimal 54 = `'6'`
   - Menggabungkan keempat karakter menghasilkan string kata sandi `"de76"`.
2. **Kelemahan Mendasar Obfuskasi Sederhana:**
   - Obfuskasi bukanlah enkripsi. Teknik substitusi representasi angka (heksadesimal atau desimal) dapat dievaluasi secara instan oleh interpreter atau analisis statis manusia tanpa membutuhkan kunci rahasia.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh artefak tantangan dari pustaka berkas CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/da3b21f411362ad5c273b3a48a829e1a6f011d43998fabc480a2b1f3585aff0b/level2.py
   wget https://challenge-files.cylabacademy.net/library/da3b21f411362ad5c273b3a48a829e1a6f011d43998fabc480a2b1f3585aff0b/level2.flag.txt.enc
   ```
2. Analisis baris verifikasi autentikasi pada `level2.py`:
   ```bash
   grep -n "user_pw ==" level2.py
   ```
   Ditemukan ekspresi:
   ```text
   18:    if( user_pw == chr(0x64) + chr(0x65) + chr(0x37) + chr(0x36) ):
   ```
3. Evaluasi nilai karakter tersebut melalui interpreter Python:
   ```bash
   python3 -c "print(chr(0x64) + chr(0x65) + chr(0x37) + chr(0x36))"
   ```
   Output:
   ```text
   de76
   ```
4. Eksekusi skrip `level2.py` dan masukkan `de76` sebagai kata sandi:
   ```bash
   python3 level2.py
   ```
   Interaksi konsol:
   ```text
   Please enter correct password for flag: de76
   Welcome back... your flag, user:
   academy{tr45h_51ng1ng_ab548076}
   ```
5. Eksekusi skrip reproduksi mandiri `scripts/solve_246_pw_crack_2.py` untuk validasi otomatis.

---

## Flag & Verifikasi

- **Flag:** `academy{tr45h_51ng1ng_ab548076}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 246, "flag": "academy{tr45h_51ng1ng_ab548076}", "correct": true}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemampuan analisis deobfuskasi dasar kode program dan pemahaman pemetaan karakter ASCII dalam heksadesimal.
  - Memahami prinsip dasar *Security through Obscurity* yang selalu gagal menahan analisis penyerang.
- **Mitigasi Defensif:**
  - **Hindari Security through Obscurity:** Mengubah bentuk representasi data kredensial (misalnya menjadi kode ASCII ordinal atau heksadesimal) tidak memberikan perlindungan kriptografis.
  - **Arsitektur Validasi Sisi Server (Server-Side Authentication):** Seluruh proses verifikasi kredensial harus didelegasikan ke endpoint server terotentikasi, bukan dilakukan di lingkungan eksekusi klien.
  - **Terapkan Analisis Kode Otomatis (SAST Linter):** Pasang aturan SonarQube, Bandit, atau Semgrep untuk mendeteksi konstruksi string mencurigakan yang berupaya menyembunyikan kata sandi.
