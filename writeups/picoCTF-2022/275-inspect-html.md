# Writeup: Inspect HTML (Challenge ID: 275)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Source Code Reconnaissance & Comment Exposure (CWE-615 / OWASP Top 10 A05:2021 Security Misconfiguration)
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{1n5p3t0r_0f_h7ml_cdc35adf}`

---

## Problem Statement & Scope

Tantangan menyajikan sebuah situs web sederhana yang memuat kutipan sejarah tentang tokoh kuno Histiaeus:
> *"Can you get the flag? Go to this website and see what you can discover."*

Spesifikasi lingkungan:
- Lingkungan web statis berbasis HTTP yang berjalan pada kontainer instans port kustom.
- Dokumen HTML utama menyajikan teks dan paragraf informatif.
- Peserta diminta menginspeksi kode sumber markup HTML untuk menemukan informasi tersembunyi yang tidak tampak pada viewport halaman web.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Pohon DOM & Komentar HTML (CWE-615):**
   - Komentar dalam HTML ditulis menggunakan penanda khusus `<!-- ... -->`.
   - Standar W3C menetapkan bahwa komentar HTML diparse oleh mesin peramban web (*browser engine*) sebagai simpul komentar (*Comment Node*) di dalam pohon DOM (*Document Object Model*), tetapi tidak dirender ke layar visual.
   - Komentar HTML dikirimkan dalam bentuk teks jelas (*cleartext*) dari server web ke peramban pengguna.

2. **Ketiadaan Kompilasi Server-Side & Pengiriman Verbatim:**
   - Berkas HTML statis disajikan secara langsung (*verbatim*) oleh peladen web tanpa penyaringan sisi peladen (*server-side sanitization*).
   - Pengembang yang meninggalkan catatan sementara, flag rahasia, atau instruksi debugging di dalam komentar HTML mengekspos data tersebut kepada siapa saja yang membuka menu *View Source* atau menggunakan kakas pengembang (*DevTools Element Inspector*).

3. **Kepatuhan NIST SP 800-115 § 4.3 (Application Security & Web Testing):**
   - Standar pengujian penetrasi NIST SP 800-115 menempatkan inspeksi kode sumber halaman (*passive source code analysis*) sebagai langkah awal penting dalam pemetaan permukaan serangan (*attack surface reconnaissance*) untuk mendeteksi potensi paparan data sensitif (*sensitive data exposure*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengambilan Kode Sumber Halaman Utama:**
   Kirimkan permintaan HTTP `GET` ke instans web target menggunakan kakas baris perintah `curl`:
   ```bash
   curl -s "http://<target_host>:<target_port>/"
   ```

2. **Analisis Markup dan Struktur DOM:**
   Periksa bagian penutup dokumen HTML sebelum tag penutup `</body>`:
   ```html
   <!DOCTYPE html>
   <html lang="en">
     <head>
       <meta charset="UTF-8">
       <title>Inspect Me</title>
     </head>
     <body>
       <h1>Inspect Me</h1>
       <p>Capture the Flag (CTF) competitions are a great way to learn cybersecurity skills.</p>
       <br>
       <p> Source: Wikipedia on Histiaeus </p>
       <!--academy{1n5p3t0r_0f_h7ml_cdc35adf}-->
     </body>
   </html>
   ```

3. **Ekstraksi Token Menggunakan Regex:**
   Saring token menggunakan pencocokan pola:
   ```bash
   curl -s "http://<target_host>:<target_port>/" | grep -o "academy{[^}]*}"
   # Output:
   # academy{1n5p3t0r_0f_h7ml_cdc35adf}
   ```

4. **Otomasi Mandiri via Skrip Python (`scripts/solve_275_inspect_html.py`):**
   ```bash
   python3 scripts/solve_275_inspect_html.py
   ```
   Keluaran:
   ```text
   [*] Solving Challenge 275: Inspect HTML
   [*] Stage 1: Inspecting HTML document structure
       [+] Document type            : HTML5 static webpage
       [+] Vulnerability class      : CWE-615 (Inclusion of Sensitive Information in Source Code Comments)
       [+] Target location          : Pre-closing </body> section
   [*] Stage 2: Carving comment token from HTML DOM markup
       [+] Extracted HTML comment   : '<!--academy{1n5p3t0r_0f_h7ml_cdc35adf}-->'
   [*] Stage 3: Normalizing recovered flag -> academy{1n5p3t0r_0f_h7ml_cdc35adf}
   [+] Reconstructed Flag: academy{1n5p3t0r_0f_h7ml_cdc35adf}

   [SUCCESS] Module 275 (Inspect HTML) fully audited and solved: academy{1n5p3t0r_0f_h7ml_cdc35adf}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{1n5p3t0r_0f_h7ml_cdc35adf}`
- **Verifikasi API Platform:** Penyerahan token melalui endpoint REST API `POST /api/submissions/` menghasilkan status **HTTP 201 Created**:
  ```json
  {
    "user": 1072359,
    "challenge": 275,
    "flag": "academy{1n5p3t0r_0f_h7ml_cdc35adf}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Relevansi Modul LKS Cyber Security (Web Application Reconnaissance):**
  - Pemeriksaan kode sumber markup merupakan prosedur pengujian standar pertama dalam setiap penilaian keamanan web LKS.
  - Sering kali komentar HTML berisi petunjuk tentang dependensi pustaka JavaScript versi lama yang rentan, jalur endpoint administrasi tersembunyi, atau catatan pengembang mengenai konfigurasi server internal.
- **Remediasi & Mitigasi Defensif Komprehensif:**
  1. **HTML Minification & Comment Stripping pada Server/Build:**
     Konfigurasikan peladen web (seperti modul `mod_pagespeed` pada Apache atau filter `gzip_static` / minifier pada Nginx) atau kakas pipeline deployment untuk menghapus seluruh blok komentar HTML sebelum respon dikirimkan ke klien.
  2. **Kebijakan Larangan Hardcoding Informasi Rahasia:**
     Terapkan aturan standar pengembangan (*coding standard*) yang melarang keras penulisan kredensial, URL staging, atau informasi sensitif di dalam komentar kode sumber apa pun.
  3. **Penggunaan Static Code Analysis (SAST):**
     Gunakan kakas linter HTML dan SAST untuk mendeteksi komentar yang memuat pola kata kunci berisiko tinggi (seperti `TODO: fix auth`, `password=`, `admin_key`, `secret`).
