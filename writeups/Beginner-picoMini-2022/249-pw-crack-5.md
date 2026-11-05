# Writeup: PW Crack 5 (Challenge ID: 249)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Full Dictionary Attack & Hash Pre-image Cracking
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones
- **Event:** Beginner picoMini 2022
- **Points:** 100
- **Flag:** `academy{h45h_sl1ng1ng_e062d0ff}`

---

## Problem Statement & Scope

Diberikan sebuah skrip verifikasi kata sandi `level5.py`, berkas hash acuan `level5.hash.bin`, berkas cipher terenkripsi `level5.flag.txt.enc`, dan sebuah berkas kamus eksternal `dictionary.txt` yang memuat seluruh kemungkinan kata sandi heksadesimal 4 digit ($16^4 = 65.536$ baris dari `0000` hingga `ffff`).

Berbeda dengan level 3 (7 kandidat) dan level 4 (100 kandidat) di mana daftar kata sandi disematkan dalam variabel kode sumber, level 5 mengharuskan peserta memproses masukan berkas kamus eksternal berukuran ratusan kilobita, melakukan parsing baris (*line-by-line streaming* dan *whitespace trimming*), mengevaluasi intisari MD5, dan menemukan kata sandi yang memvalidasi otentikasi untuk membuka bendera format `academy{...}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kerentanan Entropi Rendah & Exhaustive Keyspace Enumeration (CWE-521 / NIST SP 800-115):**
   - Ruang kunci kata sandi dibatasi secara ketat pada string heksadesimal 4 karakter.
   - Total kemungkinan kombinasi adalah:
     $$N = 16^4 = 65.536 \text{ kata sandi}$$
   - Menurut NIST SP 800-115 Bagian 5 (*Password Cracking and Analysis*), ruang kunci sebesar ini dapat dievaluasi secara tuntas (*exhaustive search*) dalam hitungan sepersekian detik tanpa membutuhkan perangkat keras akselerasi GPU.
2. **Ketiadaan Salt dan Kecepatan Komputasi MD5:**
   - Hash MD5 tidak menggunakan salt atau faktor kerja memori. Pada prosesor modern berbasis x86_64, satu inti CPU dapat menghitung jutaan hash MD5 per detik.
   - Menguji seluruh 65.536 entri hanya memerlukan waktu $\approx 35$ milidetik pada interpreter Python murni.
3. **Pencocokan Pre-image & Dekripsi Simetris:**
   - Evaluasi terhadap `dictionary.txt` menemukan kecocokan intisari MD5 pada token `"7e5f"`.
   - Menggunakan `"7e5f"` pada rutin `str_xor(flag_enc, "7e5f")` menghasilkan teks terang bendera.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh seluruh artefak dari repositori pustaka berkas CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/level5.py
   wget https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/level5.flag.txt.enc
   wget https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/level5.hash.bin
   wget https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/dictionary.txt
   ```
2. Buat skrip pembaca kamus dan perayap hash MD5:
   ```python
   import hashlib

   target_hash = open("level5.hash.bin", "rb").read()

   with open("dictionary.txt", "r") as f:
       for line in f:
           candidate = line.strip()
           if hashlib.md5(candidate.encode()).digest() == target_hash:
               print(f"[+] Kata sandi valid ditemukan: {candidate}")
               break
   ```
3. Eksekusi skrip perayap kamus:
   ```bash
   python3 crack_level5.py
   ```
   Output:
   ```text
   [+] Kata sandi valid ditemukan: 7e5f
   ```
4. Masukkan kata sandi `7e5f` ke dalam prompt `level5.py`:
   ```bash
   python3 level5.py
   ```
   Interaksi konsol:
   ```text
   Please enter correct password for flag: 7e5f
   Welcome back... your flag, user:
   academy{h45h_sl1ng1ng_e062d0ff}
   ```
5. Eksekusi skrip reproduksi mandiri `scripts/solve_249_pw_crack_5.py` untuk validasi otomatis menyeluruh.

---

## Flag & Verifikasi

- **Flag:** `academy{h45h_sl1ng1ng_e062d0ff}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 249, "flag": "academy{h45h_sl1ng1ng_e062d0ff}", "correct": true}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemampuan integrasi berkas kamus eksternal (*Wordlist/Dictionary Processing*) dalam skenario audit keamanan kata sandi dan penilaian kerentanan autentikasi.
  - Memahami korelasi antara panjang karakter, *character space*, dan estimasi waktu peretasan (*time-to-crack estimation*).
- **Mitigasi Defensif:**
  - **Penetapan Kebijakan Kompleksitas & Panjang Minimal (NIST SP 800-63B):** Jangan pernah mengizinkan penggunaan kata sandi berbasis kombinasi heksadesimal pendek 4 karakter. Tetapkan ambang batas panjang minimal yang memadai.
  - **Skema Pengacakan Garam (Cryptographic Salt):** Terapkan salt acak dengan panjang minimum 128 bit per akun agar penyerang tidak dapat menggunakan daftar kata sandi atau hash terhitung sebelumnya secara massal.
  - **Mekanisme Throttling & CAPTCHA:** Terapkan perlindungan perlambatan waktu respons (*exponential backoff delay*) atau CAPTCHA setelah kegagalan login beruntun untuk melumpuhkan upaya perayapan kamus otomatis.
