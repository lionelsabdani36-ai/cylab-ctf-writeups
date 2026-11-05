# Writeup: PW Crack 3 (Challenge ID: 247)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Dictionary Hash Pre-image & Password Cracking
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones
- **Event:** Beginner picoMini 2022
- **Points:** 75
- **Flag:** `academy{m45h_fl1ng1ng_b8034615}`

---

## Problem Statement & Scope

Diberikan sebuah skrip Python bernama `level3.py`, berkas hash biner `level3.hash.bin`, dan berkas cipher terenkripsi `level3.flag.txt.enc`. Pada varian ini, verifikasi kata sandi tidak lagi menggunakan perbandingan langsung terhadap string terang atau representasi karakter terobfuskasi, melainkan membandingkan intisari (*digest*) hash MD5 dari masukan pengguna dengan hash tersimpan di berkas biner.

Skrip mendefinisikan daftar 7 kandidat kata sandi potensial pada variabel `pos_pw_list`:
```python
pos_pw_list = ["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"]
```
Peserta ditugaskan untuk melakukan analisis hash pre-image terhadap ruang pencarian terbatas tersebut, mengidentifikasi kata sandi yang valid, mendekripsi ciphertext, dan memulihkan token bendera resmi format `academy{...}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Penggunaan Algoritma Hashing Usang (CWE-327 / NIST SP 800-115):**
   - Fungsi verifikasi menggunakan MD5 (*Message Digest Algorithm 5*):
     ```python
     def hash_pw(pw_str):
         pw_bytes = bytearray()
         pw_bytes.extend(pw_str.encode())
         m = hashlib.md5()
         m.update(pw_bytes)
         return m.digest()
     ```
   - MD5 tidak dirancang untuk penyimpanan kredensial karena ketiadaan *computational cost* yang dapat disesuaikan (*work factor*), ketiadaan salt kriptografis secara default, dan rentan terhadap pencarian pre-image/tabel pelangi (*rainbow table*).
2. **Ruang Entropi Kandidat Sangat Rendah (Weak Entropy & Small Key Space):**
   - Penyerang disajikan daftar eksplisit 7 kandidat kata sandi. Kompleksitas komputasi serangan kamus (*dictionary attack*) pada tantangan ini adalah $\mathcal{O}(N)$ dengan $N = 7$.
   - Mengevaluasi MD5 terhadap 7 string membutuhkan waktu kurang dari 1 milidetik pada CPU standar.
3. **Kesesuaian Hash & Pemulihan Plaintext:**
   - Menghitung $\text{MD5}(p)$ untuk setiap $p \in \text{pos\_pw\_list}$ dan mencocokkannya dengan 16 bita data biner pada `level3.hash.bin` mengidentifikasi kata sandi asli: `"ec27"`.
   - String `"ec27"` kemudian dipakai sebagai kunci simetris aliran XOR pada `str_xor(flag_enc, "ec27")` untuk mendekripsi bendera.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh ketiga artefak dari repositori pustaka berkas CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/0b854ebb7dc61eaf9e9781840b77b52a5044c592a2ad693c8a8e4637b8c2e07d/level3.py
   wget https://challenge-files.cylabacademy.net/library/0b854ebb7dc61eaf9e9781840b77b52a5044c592a2ad693c8a8e4637b8c2e07d/level3.flag.txt.enc
   wget https://challenge-files.cylabacademy.net/library/0b854ebb7dc61eaf9e9781840b77b52a5044c592a2ad693c8a8e4637b8c2e07d/level3.hash.bin
   ```
2. Baca daftar kandidat kata sandi dari akhir berkas `level3.py`:
   ```bash
   tail -n 5 level3.py
   ```
   Ditemukan:
   ```text
   pos_pw_list = ["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"]
   ```
3. Lakukan pengujian hash otomatis menggunakan skrip satu baris Python:
   ```bash
   python3 -c '
   import hashlib
   target = open("level3.hash.bin", "rb").read()
   candidates = ["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"]
   for c in candidates:
       if hashlib.md5(c.encode()).digest() == target:
           print("Matched Password:", c)
   '
   ```
   Hasil pencocokan:
   ```text
   Matched Password: ec27
   ```
4. Eksekusi `level3.py` dan masukkan kata sandi `ec27`:
   ```bash
   python3 level3.py
   ```
   Interaksi konsol:
   ```text
   Please enter correct password for flag: ec27
   Welcome back... your flag, user:
   academy{m45h_fl1ng1ng_b8034615}
   ```
5. Eksekusi skrip reproduksi mandiri `scripts/solve_247_pw_crack_3.py` untuk validasi menyeluruh.

---

## Flag & Verifikasi

- **Flag:** `academy{m45h_fl1ng1ng_b8034615}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 247, "flag": "academy{m45h_fl1ng1ng_b8034615}", "correct": true}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemampuan analisis integritas dan pencocokan hash kriptografis (*Cryptographic Hash Assessment*) sesuai panduan NIST SP 800-115 Bagian 5 (Password Cracking and Analysis).
  - Mengembangkan otomasi penyerangan berbasis kamus (*dictionary-based password cracking automation*) untuk menembus kontrol akses dengan ruang entropi rendah.
- **Mitigasi Defensif:**
  - **Peningkatan Algoritma Penyimpanan Kredensial:** Tinggalkan fungsi hash cepat serbaguna seperti MD5 atau SHA-1 untuk kredensial. Terapkan fungsi pembentukan kunci aman yang lambat (*Slow Password Hashing Function*) seperti Argon2id, bcrypt, atau PBKDF2 dengan faktor iterasi tinggi.
  - **Penerapan Salt Kriptografis Acak (CWE-759):** Selalu gunakan salt acak unik per pengguna minimal 16 bita sebelum proses hashing agar terlindung dari serangan tabel pra-hitung (*precomputed rainbow table*).
  - **Pembatasan Laju Percobaan (Rate Limiting & Account Lockout):** Batasi jumlah upaya pemasukan kata sandi pada layanan autentikasi untuk memitigasi serangan brute-force secara interaktif.
