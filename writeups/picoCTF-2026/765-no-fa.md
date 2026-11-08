# Writeup: No FA (Challenge ID: 765)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Authentication & 2FA (NIST SP 800-115 §4.2)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** Darkraicg492
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{n0_r4t3_n0_4uth_96369057}`
- **Flag Komunitas:** `CTF{n0_r4t3_n0_4uth_96369057}`

---

## Problem Statement & Scope

Tantangan mengevaluasi keandalan implementasi otentikasi multi-faktor (2FA) dan manajemen sesi pada aplikasi web modern:
> *"Seems like some data has been leaked! Can you get the flag?"*

Layanan menyajikan aplikasi berbasis framework Python Flask. Terjadi insiden kebocoran data (*data leakage*) yang mengekspos berkas kode sumber aplikasi `app.py` dan basis data relasional SQLite `users.db`. Sistem mengharuskan otentikasi dua langkah: login awal dengan username dan kata sandi, dilanjutkan dengan verifikasi kode OTP 4-digit. Nilai flag hanya dirender pada endpoint root `/` jika sesi memiliki atribut `session['username'] == 'admin'` dan `session['logged'] == 'true'`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

Audit kode sumber dan konfigurasi aplikasi mengidentifikasi kelemahan berlapis pada arsitektur kriptografi dan mekanisme otentikasi:

1. **CWE-916 / Penggunaan Algoritma Hashing Tanpa Salt (Unsalted SHA-256 Storage):**
   - Basis data `users.db` menyimpan kata sandi 20 akun menggunakan kalkulasi hash langsung:
     $$\text{hash} = \text{SHA-256}(\text{password})$$
   - Ketiadaan *cryptographic salt* memungkinkan serangan *dictionary lookup* dan *rainbow table*.
   - Hash milik akun `admin`:
     `c20fa16907343eef642d10f0bdb81bf629e6aaf6c906f26eabda079ca9e5ab67`
     Dapat di-crack secara instan menggunakan wordlist standar `rockyou.txt` menjadi kata sandi sederhana: `apple@123`.

2. **CWE-307 / Ketiadaan Pembatasan Percobaan Otentikasi (Unthrottled 2FA Verification):**
   - Kode OTP dihasilkan sebagai integer acak 4-digit menggunakan fungsi `random.randint(1000, 9999)`:
     $$N_{\text{kandidat}} = 9000$$
   - Ruang kunci 9.000 kombinasi sangat kecil (*low entropy*).
   - Masa berlaku OTP disetel selama 120 detik, namun rute verifikasi `POST /two_fa` sama sekali tidak menerapkan *rate-limiting*, *CAPTCHA*, ataupun *account lockout policy*.

3. **CWE-384 / Ketiadaan Invalidasi Percobaan pada Sesi Bersama (Race-Condition Exhaustion):**
   - Nilai OTP terikat pada cookie sesi Flask klien. Setiap kali pengguna melakukan otentikasi ulang, kode OTP di-refresh.
   - Karena endpoint verifikasi tidak membatasi kuota kegagalan (misalnya 3 kali salah langsung blokir), penyerang dapat mempertahankan **satu sesi otentikasi aktif** dan meluncurkan serangan konkurensi paralel (50 thread) untuk menguji rentang 1000–9999. Seluruh 9.000 kombinasi dapat dihabiskan dalam waktu sekitar 40–50 detik, jauh sebelum batas waktu 120 detik berakhir.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Forensik Basis Data SQLite & Cracking Kredensial:**
   - Membaca skema tabel dari berkas `users.db`:
     ```sql
     SELECT username, password, two_fa FROM users WHERE username = 'admin';
     ```
   - Mengambil hash `c20fa16907343eef642d10f0bdb81bf629e6aaf6c906f26eabda079ca9e5ab67`.
   - Menguji komparasi kamus:
     ```python
     hashlib.sha256(b"apple@123").hexdigest() == admin_hash
     ```
   - Kredensial admin dipulihkan: `admin:apple@123`.

2. **Inisialisasi Sesi Otentikasi Tunggal:**
   - Mengirim request `POST /login` dengan payload:
     ```json
     {"username": "admin", "password": "apple@123"}
     ```
   - Menyimpan cookie sesi Flask `session` yang diterbitkan server.

3. **Otomasi Brute-Force Paralel Multi-Thread:**
   - Membagi ruang uji 1000–9999 ke dalam 50 pekerja thread (`threading.Thread`), masing-masing menangani blok 180–200 kode OTP.
   - Mengirim request `POST /two_fa` dengan parameter `otp=XXXX` menggunakan handler cookie sesi yang sama.
   - Saat kode yang cocok tercapai (misal `8863`), respons server berubah menjadi indikator keberhasilan otentikasi.

4. **Pengambilan Flag Administrasi:**
   - Melakukan request `GET /` dengan sesi terverifikasi tersebut.
   - Template Flask merender nilai flag yang tersimpan pada variabel lingkungan server.
   - Skrip reproduktif: `scripts/solve_765_no_fa.py`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{n0_r4t3_n0_4uth_96369057}`
- **Format Flag Komunitas:** `CTF{n0_r4t3_n0_4uth_96369057}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 765, "flag": "academy{n0_r4t3_n0_4uth_96369057}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Penerapan Hashing Kata Sandi Adaptif Ber-Salt (NIST SP 800-63B §5.1.1):**
   - Jangan pernah menggunakan fungsi hash kriptografis cepat (`MD5`, `SHA-1`, `SHA-256`) tanpa salt untuk verifikasi kata sandi.
   - Wajibkan algoritma *memory-hard / compute-hard* seperti Argon2id atau bcrypt dengan salt acak unik per pengguna (minimal 128 bit) dan work factor terkalibrasi.
2. **Penguatan Mekanisme Multi-Factor Authentication (CWE-307 Remediation):**
   - Kode OTP berbasis waktu (*time-based*) atau SMS wajib memiliki panjang minimal 6 digit (1.000.000 kemungkinan) hingga 8 digit, digenerate melalui generator acak terstandar kriptografi (`secrets.SystemRandom`), bukan modul pseudorandom bawaan (`random.randint`).
   - Terapkan mekanisme *anti-automation*: batasi percobaan maksimal 3 hingga 5 kali per sesi OTP. Jika ambang batas terlampaui, batalkan OTP secara permanen dan kunci sementara akun bersangkutan (*exponential backoff / temporary lockout*).
3. **Pemberian Masa Berlaku dan Invalidasi Sekali Pakai (Single-Use Token):**
   - Setiap kode verifikasi OTP harus langsung di-invalida-si dari sesi/basis data segera setelah satu kali percobaan verifikasi diproses (baik berhasil maupun gagal), sehingga menutup celah eksploitasi konkurensi paralel (*race condition*).
