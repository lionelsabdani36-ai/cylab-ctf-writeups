# Writeup: Chronohack (Challenge ID: 468)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Insecure Millisecond PRNG Seeding & State Prediction
- **Difficulty:** Medium (2)
- **Points:** 200 (CyLab) / 200 (picoCTF)
- **Author:** Theoneste Byagutangaza
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{UseSecure#$_Random@j3n3r@T0rs2627fc3a}`
- **Flag Platform Asli:** `picoCTF{UseSecure#$_Random@j3n3r@T0rs2627fc3a}`
- **Flag Komunitas:** `CTF{UseSecure#$_Random@j3n3r@T0rs2627fc3a}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Assessment), NIST SP 800-90A Rev. 1 (Recommendation for Random Number Generation Using Deterministic Random Bit Generators), RFC 4086 (Randomness Requirements for Security), CWE-330 (Use of Insufficiently Random Values), & CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Reverse Engineering, Software Security & Insecure Randomness*:
- **Skenario Tantangan:** Sistem verifikasi institusi pendidikan mengandalkan mekanisme token generator baris perintah berbasis Python (`token_generator.py`) untuk memvalidasi identitas siswa. Berkas kode sumber generator bocor ke publik. Peserta berinteraksi dengan layanan socket jaringan interaktif yang meminta penebakan token 20 karakter dengan batasan maksimal 50 kali percobaan per koneksi sebelum program keluar (*exhausted attempts*).
- **Deskripsi Soal:** *"Can you guess the exact token and unlock the hidden flag? Our school relies on tokens to authenticate students. Unfortunately, someone leaked an important file for token generation. Guess the token to get the flag. Hints: https://www.epochconverter.com/ | https://learn.snyk.io/lesson/insecure-randomness/ | Time tokens generation | Generate tokens for a range of seed values very close to the target time"*
- **Batasan Lingkungan & Scope Audit:**
  1. Koneksi socket TCP on-demand CyLab (`nc host port`).
  2. Dekonstruksi berkas sumber `token_generator.py` yang leaked dari CDN CyLab.
  3. Pemodelan matematis siklus internal generator bilangan acak semu (PRNG) Python `random` (algoritma Mersenne Twister MT19937).
  4. Penyelarasan selisih waktu jaringan (*clock synchronization & round-trip time latency*) untuk membatasi jendela pencarian seed dalam rentang milidetik.
  5. Automasi interaksi socket TCP untuk mengirimkan hingga 50 tebakan deterministik dalam satu sesi koneksi.
  6. Verifikasi live submission melalui REST API CyLab `POST /api/submissions/` (HTTP Status 201 Created).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kelemahan Mersenne Twister untuk Konteks Keamanan (CWE-338 / NIST SP 800-90A):**
   Modul standar `random` pada bahasa pemrograman Python mengimplementasikan algoritma Mersenne Twister (MT19937) dengan periode $2^{19937}-1$. Karakteristik algoritma ini:
   - Dirancang untuk kecepatan komputasi dan distribusi statistik seragam pada simulasi numerik (*Monte Carlo simulations*).
   - Sama sekali tidak memenuhi standar ketahanan kriptografis (*not cryptographically secure*).
   - Nilai keluaran berikutnya sepenuhnya dapat diprediksi secara deterministik apabila status internal (624 bilangan bulat 32-bit) atau nilai awal (*seed*) diketahui.

2. **Insecure Seeding Berbasis Waktu Epok Milidetik (CWE-330 / RFC 4086):**
   Fungsi `get_random` pada `token_generator.py` menginisialisasi status generator dengan:
   ```python
   random.seed(int(time.time() * 1000))
   ```
   Penggunaan stempel waktu UNIX saat ini dalam satuan milidetik menimbulkan bencana keamanan:
   - Ruang pencarian (*keyspace*) tidak lagi sebesar $2^{19937}$, melainkan menyusut drastis ke interval waktu singkat saat fungsi dieksekusi.
   - Karena klien dan server berkomunikasi secara real-time, waktu inisiasi koneksi socket TCP klien ($t_0$) hanya berselisih beberapa ratus milidetik dari waktu eksekusi `get_random` di peladen.
   - Rentang offset $[t_0 \times 1000 - 200, t_0 \times 1000 + 1500]$ milidetik hanya memuat kurang dari 2000 kemungkinan bilangan bulat.
   - Mengingat server memberikan toleransi hingga 50 kali tebakan per koneksi, penyerang hanya membutuhkan beberapa kali percobaan koneksi atau pembagian batch probing untuk menemukan seed yang tepat dengan probabilitas 100%.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Berkas Bocor `token_generator.py`:**
   Membaca alur fungsi pembuatan token:
   ```python
   alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
   random.seed(int(time.time() * 1000))
   s = "".join(random.choice(alphabet) for _ in range(20))
   ```

2. **Penyelarasan Waktu & Konstruksi Generator Deterministik Lokal:**
   Membangun fungsi emulasi lokal:
   ```python
   def generate_token(seed: int, length: int = 20) -> str:
       random.seed(seed)
       return "".join(random.choice(ALPHABET) for _ in range(length))
   ```

3. **Inisiasi Socket & Probing Jendela Milidetik:**
   - Klien mencatat waktu lokal $t_0$ tepat sebelum membuka koneksi socket ke server lab.
   - Menerima prompt `Enter your guess for the token (or exit):`.
   - Mengirimkan kandidat token secara berurutan untuk rentang seed:
     $$\text{seed}_i = \lfloor t_0 \times 1000 \rfloor + \text{offset} + i$$
     dengan $i \in [0, 39]$.

4. **Ekstraksi Token & Penerimaan Flag:**
   Saat token yang dikirimkan cocok dengan hasil kalkulasi server, server mengeksekusi fungsi `flag()` dan memancarkan teks berkas `/flag.txt`:
   ```text
   Congratulations! You found the correct token.
   academy{UseSecure#$_Random@j3n3r@T0rs2627fc3a}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{UseSecure#$_Random@j3n3r@T0rs2627fc3a}`
- **Flag Platform Asli:** `picoCTF{UseSecure#$_Random@j3n3r@T0rs2627fc3a}`
- **Status API Verification:** `POST /api/submissions/` mengembalikan respons `HTTP 201 Created` dengan `{"correct": true, "status": "correct"}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Penggunaan Pembangkit Bilangan Acak Aman Kriptografis (CSPRNG):**
   Untuk pembuatan rahasia sesi, token autentikasi, kunci API, atau nilai nonce, pengembang dilarang menggunakan modul `random` bawaan. Pengembang wajib beralih ke modul `secrets` standar Python (sejak Python 3.6):
   ```python
   import secrets

   def get_secure_token(length: int = 32) -> str:
       return secrets.token_urlsafe(length)
   ```
   Modul `secrets` memanfaatkan entropi perangkat keras sistem operasi (`/dev/urandom` atau CryptGenRandom) yang tidak dapat diprediksi oleh pihak luar.

2. **Pembatasan Percobaan & Pengamanan Status Sesi (Defense-in-Depth):**
   - Terapkan mekanisme pembatasan laju (*rate limiting*) ketat dan *exponential backoff* pada kegagalan verifikasi token.
   - Hindari mengekspos siklus hidup token langsung ke antarmuka terminal publik tanpa otentikasi identitas awal.
