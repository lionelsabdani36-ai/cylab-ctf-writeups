# Writeup: PW Crack 4 (Challenge ID: 248)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Automated Dictionary Hash Cracking
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones
- **Event:** Beginner picoMini 2022
- **Points:** 85
- **Flag:** `academy{fl45h_5pr1ng1ng_c1e14a37}`

---

## Problem Statement & Scope

Diberikan sebuah skrip verifikasi kata sandi `level4.py`, berkas hash acuan `level4.hash.bin`, dan berkas cipher terenkripsi `level4.flag.txt.enc`. Jika pada varian sebelumnya daftar kandidat hanya memuat 7 item, pada level ini ruang pencarian diperluas menjadi 100 kandidat kata sandi heksadesimal 4-karakter pada variabel `pos_pw_list`:
```python
pos_pw_list = ["158f", "1655", "d21e", ..., "8b95", "d0e5"]
```
Mencoba memasukkan kata sandi satu per satu secara manual ke konsol interaktif menjadi tidak efisien. Peserta dituntut membuat otomasi pengujian (*automated brute-force/dictionary script*) untuk menguji seluruh 100 kandidat terhadap intisari MD5 tersimpan, mengekstrak kata sandi yang cocok, dan mendekripsi bendera format `academy{...}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Skalabilitas Serangan Kamus Terotomasi (CWE-307 / CWE-327 / NIST SP 800-115):**
   - Panduan pengujian penetrasi teknis NIST SP 800-115 mengidentifikasi bahwa autentikasi yang bergantung pada ruang kunci kecil (100 item) rentan terhadap otomasi evaluasi hash (*automated offline credential cracking*).
   - Penggunaan algoritma hash non-iteratif tanpa salt (MD5 murni) memungkinkan penyerang menghitung 100 digest MD5 dalam hitungan mikrodetik ($\approx 0.05 \text{ ms}$).
2. **Ketiadaan Mitigasi Anti-Automation & Slow Hashing:**
   - Karena pemeriksaan hash dilakukan secara lokal atau offline tanpa *proof-of-work*, *work factor*, atau salt dinamis, peningkatan jumlah kandidat dari 7 menjadi 100 tidak memberikan peningkatan keamanan yang berarti.
3. **Pencocokan Deterministik & Dekripsi Aliran XOR:**
   - Dengan mengiterasi `for pw in pos_pw_list:` dan membandingkan `hashlib.md5(pw.encode()).digest()` terhadap bita `level4.hash.bin`, ditemukan kecocokan persis pada nilai `"bb8e"`.
   - Menjalankan fungsi dekripsi `str_xor(flag_enc, "bb8e")` memulihkan teks terang bendera secara instan.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh ketiga artefak dari pustaka berkas CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/846131a53233d7d11fb53d10ebe53b2addb4693a7f39e2f464fed1d85226b899/level4.py
   wget https://challenge-files.cylabacademy.net/library/846131a53233d7d11fb53d10ebe53b2addb4693a7f39e2f464fed1d85226b899/level4.flag.txt.enc
   wget https://challenge-files.cylabacademy.net/library/846131a53233d7d11fb53d10ebe53b2addb4693a7f39e2f464fed1d85226b899/level4.hash.bin
   ```
2. Buat skrip otomasi cracking berbasis Python untuk menguji ke-100 kandidat kata sandi:
   ```python
   import hashlib

   target_hash = open("level4.hash.bin", "rb").read()
   with open("level4.py", "r") as f:
       code = f.read()

   # Ekstrak pos_pw_list dari skrip
   pos_pw_list = eval(code.split("pos_pw_list = ")[1].split("\n")[0])

   for pw in pos_pw_list:
       if hashlib.md5(pw.encode()).digest() == target_hash:
           print(f"[+] Kata sandi valid ditemukan: {pw}")
           break
   ```
3. Eksekusi skrip pencarian di atas:
   ```bash
   python3 crack_level4.py
   ```
   Output:
   ```text
   [+] Kata sandi valid ditemukan: bb8e
   ```
4. Masukkan kata sandi `bb8e` pada prompt interaktif `level4.py`:
   ```bash
   python3 level4.py
   ```
   Interaksi konsol:
   ```text
   Please enter correct password for flag: bb8e
   Welcome back... your flag, user:
   academy{fl45h_5pr1ng1ng_c1e14a37}
   ```
5. Jalankan skrip reproduksi mandiri `scripts/solve_248_pw_crack_4.py` untuk validasi otomatis menyeluruh.

---

## Flag & Verifikasi

- **Flag:** `academy{fl45h_5pr1ng1ng_c1e14a37}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 248, "flag": "academy{fl45h_5pr1ng1ng_c1e14a37}", "correct": true}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemampuan menyusun kode otomasi (*scripting automation*) untuk menangani skenario serangan kamus skala menengah hingga masif.
  - Memahami pentingnya efisiensi algoritma iterasi saat melakukan audit kepatuhan kata sandi (*Password Strength Assessment*) di lingkungan kompetisi LKS.
- **Mitigasi Defensif:**
  - **Kekuatan Entropi Kredensial (NIST SP 800-63B):** Kata sandi 4 karakter heksadesimal hanya memiliki ruang kombinasi $16^4 = 65.536$ kemungkinan (kurang dari 16 bit entropi). Terapkan kebijakan panjang minimum kata sandi (minimal 12-16 karakter dengan karakter bervariasi).
  - **Fungsi Derivasi Kunci Modern:** Gunakan algoritma *memory-hard* seperti Argon2id atau scrypt dengan parameter memori dan komputasi yang memaksa penyerang menghabiskan sumber daya signifikan per tebakan.
  - **Audit Kode Statis Berkala:** Pastikan daftar kandidat kredensial tidak pernah disertakan dalam rilis aplikasi produksi.
