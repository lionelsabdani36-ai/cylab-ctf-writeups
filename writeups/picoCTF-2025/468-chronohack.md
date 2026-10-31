# Writeup: Chronohack (Challenge ID: 468)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Insecure PRNG Seeding & Time-based Token Prediction
- **Difficulty:** Medium
- **Author:** CyLab Security Team
- **Event:** picoCTF 2025
- **Points:** 200
- **Flag:** `academy{UseSecure#$_Random@j3n3r@T0rs2627fc3a}`

---

## Problem Statement & Scope
Sistem autentikasi sekolah menggunakan mekanisme token generator berbasis script Python (`token_generator.py`) untuk memvalidasi akses siswa. Kode sumber generator bocor ke publik. Penyerang diberikan layanan jaringan interaktif yang meminta penyerang menebak token 20 karakter dengan batasan maksimal 50 kali percobaan per koneksi sebelum program keluar.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Insecure Randomness (CWE-330 / NIST SP 800-90A)
Pada file `token_generator.py`, token dibuat menggunakan pustaka bawaan `random`:
```python
def get_random(length):
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    random.seed(int(time.time() * 1000))
    s = ""
    for i in range(length):
        s += random.choice(alphabet)
    return s
```
Pustaka `random` Python mengimplementasikan algoritma Mersenne Twister (MT19937) yang bersifat deterministik dan tidak dirancang untuk tujuan keamanan kriptografi (*not cryptographically secure*).

### 2. Prediktabilitas Seed Berbasis Waktu Epok Milidetik
Fungsi `random.seed(int(time.time() * 1000))` mendasarkan nilai awal generator pada stempel waktu UNIX saat ini dalam satuan milidetik.
Karena latensi jaringan dan sinkronisasi jam antar peladen awan (*cloud clock offset*) umumnya berada dalam selisih beberapa ratus milidetik, penyerang yang mencatat waktu awal inisiasi koneksi ($T_0$) dapat membatasi ruang pencarian seed ke rentang sempit $[T_0 - 200\text{ ms}, T_0 + 1500\text{ ms}]$.
Dengan jatah 40–50 tebakan per koneksi, penyerang dapat menyapu seluruh rentang kandidat dalam beberapa koneksi berurutan.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis File Generator Sumber:**
   Unduh file `token_generator.py` dari CDN CyLab. Teridentifikasi bahwa panjang token adalah 20 karakter dengan alfabet 62 simbol (`[0-9A-Za-z]`).
2. **Implementasi Token Replicator Lokal:**
   Buat replika lokal fungsi `generate_token(seed)` yang menerima bilangan bulat seed spesifik.
3. **Penyelarasan Waktu Koneksi & Probing:**
   - Catat `t0 = time.time()`.
   - Bangun koneksi socket TCP ke `chatelaine.cylabacademy.net:38972`.
   - Uji kandidat seed dengan offset inkremental 1 milidetik:
     $$\text{seed}_i = \lfloor t_0 \times 1000 \rfloor + \text{offset} + i$$
4. **Verifikasi Token Sukses:**
   Pada window offset sekitar $+330$ hingga $+394$ milidetik (memperhitungkan waktu round-trip TCP hand-shake dan spawn proses container server), token yang dihasilkan oleh seed `1793449003394` (`eKVG7GKkjToAhRfi8GGl`) cocok 100% dengan token server.
5. **Penerimaan Flag:**
   ```text
   Congratulations! You found the correct token.
   academy{UseSecure#$_Random@j3n3r@T0rs2627fc3a}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{UseSecure#$_Random@j3n3r@T0rs2627fc3a}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true, "status": 201}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Larangan Penggunaan Mersenne Twister untuk Token Rahasia:** Modul standar `random` di Python, `rand()` di C/PHP, atau `Math.random()` di JavaScript tidak boleh digunakan untuk menghasilkan rahasia sesi, token reset password, atau token autentikasi.
- **Penerapan CSPRNG (Cryptographically Secure Pseudo-Random Number Generator):** Gunakan modul `secrets` di Python (`secrets.token_urlsafe(32)` atau `secrets.choice`), fungsi `os.urandom()`, atau `/dev/urandom` sistem operasi yang memanfaatkan entropi perangkat keras (*hardware entropy pool*).
- **Pembatasan Rate Limiting & Hashing Token:** Token autentikasi di sisi peladen harus disimpan dalam bentuk hash yang aman dan dibatasi dengan mekanisme exponential backoff / IP rate limiting untuk menggagalkan upaya pencocokan serial.
