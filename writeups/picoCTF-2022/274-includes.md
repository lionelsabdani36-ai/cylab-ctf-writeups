# Writeup: Includes (Challenge ID: 274)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Asset Enumeration & Comment Exposure (CWE-615 / OWASP Top 10 A05:2021 Security Misconfiguration)
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{1nclu51v17y_1of2_f7w_2of2_ce526b3b}`

---

## Problem Statement & Scope

Tantangan menyajikan sebuah situs web sederhana yang menjelaskan konsep direktif berkas dalam pengembangan web:
> *"Can you get the flag? Go to this website and see what you can discover."*

Spesifikasi lingkungan:
- Lingkungan web statis berbasis HTTP yang berjalan pada kontainer instans port kustom.
- Dokumen HTML utama (`index.html`) memuat teks edukatif serta memanggil berkas gaya presentasi (`style.css`) dan skrip klien (`script.js`).
- Peserta diminta mengidentifikasi kebocoran kredensial atau token rahasia yang terdistribusi di antara berkas-berkas eksternal pendukung yang dimuat oleh dokumen HTML utama.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Pemisahan Sumber Daya Eksternal Web (Separation of Concerns):**
   - Arsitektur web memisahkan struktur semantik (HTML), tata letak presentasi visual (CSS), dan perilaku logika interaktif (JavaScript) ke dalam berkas-berkas terpisah.
   - Dokumen HTML menghubungkan berkas-berkas tersebut menggunakan tag `<link rel="stylesheet" href="style.css">` dan `<script src="script.js"></script>`.
   - Browser klien mengunduh seluruh aset tertaut tersebut secara otomatis melalui permintaan HTTP `GET` terpisah tanpa memerlukan otentikasi tambahan.

2. **Kebocoran Informasi Sensitif Melalui Komentar Kode Sumber (CWE-615):**
   - Sintaks komentar pada CSS (`/* ... */`) dan JavaScript (`// ...` serta `/* ... */`) dirancang untuk dokumentasi internal pengembang.
   - Pengembang sering kali meninggalkan catatan konfigurasi, kunci akses sementara, atau pecahan token di dalam komentar berkas pendukung.
   - Karena berkas statis disajikan secara langsung (*verbatim*) oleh web server tanpa melalui tahap kompilasi atau minifikasi (*stripping*), seluruh teks komentar dapat dibaca bebas oleh pihak luar yang memeriksa respons HTTP.

3. **Kepatuhan NIST SP 800-115 § 4.3 (Application Security & Web Testing):**
   - Standar pengujian penetrasi NIST SP 800-115 mengamanatkan fase inspeksi kode sumber dan analisis aset eksternal (*asset reconnaissance*) untuk mendeteksi paparan informasi sensitif (*information leakage*) sebelum melangkah ke pengujian eksploitasi aktif.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Dokumen HTML Utama:**
   Lakukan permintaan HTTP `GET` ke alamat dasar web:
   ```bash
   curl -s "http://<target_host>:<target_port>/"
   ```
   Potongan keluaran HTML menunjukkan pemanggilan dua berkas statis eksternal:
   ```html
   <!DOCTYPE html>
   <html lang="en">
     <head>
       <meta charset="UTF-8">
       <link rel="stylesheet" href="style.css">
       <title>Includes</title>
     </head>
     <body>
       <h1>Includes</h1>
       <p>This is a website with some includes.</p>
       <script src="script.js"></script>
     </body>
   </html>
   ```

2. **Ekstraksi Aset Gaya Lembar Kerja (`style.css`):**
   Unduh berkas CSS yang ditautkan:
   ```bash
   curl -s "http://<target_host>:<target_port>/style.css"
   ```
   Keluaran berkas:
   ```css
   body {
     background-color: lightblue;
   }
   /*  academy{1nclu51v17y_1of2_  */
   ```
   Ditemukan bagian pertama token: `academy{1nclu51v17y_1of2_`.

3. **Ekstraksi Aset Skrip Klien (`script.js`):**
   Unduh berkas JavaScript yang ditautkan:
   ```bash
   curl -s "http://<target_host>:<target_port>/script.js"
   ```
   Keluaran berkas:
   ```javascript
   function greetings() {
     alert("This code is in a separate file!");
   }
   //  f7w_2of2_ce526b3b}
   ```
   Ditemukan bagian kedua token: `f7w_2of2_ce526b3b}`.

4. **Rekonstruksi Token Lengkap:**
   Penggabungan kedua segmen menghasilkan token valid:
   $$\text{Bagian 1} + \text{Bagian 2} = \text{"academy\{1nclu51v17y\_1of2\_"} + \text{"f7w\_2of2\_ce526b3b\}"} = \text{"academy\{1nclu51v17y\_1of2\_f7w\_2of2\_ce526b3b\}"}$$

5. **Otomasi Mandiri via Skrip Python (`scripts/solve_274_includes.py`):**
   ```bash
   python3 scripts/solve_274_includes.py
   ```
   Keluaran:
   ```text
   [*] Solving Challenge 274: Includes
   [*] Stage 1: Enumerating HTML source and external dependencies
       [+] HTML references linked stylesheet: <link rel='stylesheet' href='style.css'>
       [+] HTML references linked script    : <script src='script.js'></script>
       [+] Vulnerability classification     : CWE-615 (Information Exposure Through Comments)
   [*] Stage 2: Carving multipart flag tokens from external assets
       [+] Carved CSS comment token (Part 1) : 'academy{1nclu51v17y_1of2_'
       [+] Carved JS comment token (Part 2)  : 'f7w_2of2_ce526b3b}'
   [*] Stage 3: Assembling multipart segments -> academy{1nclu51v17y_1of2_f7w_2of2_ce526b3b}
   [+] Reconstructed Flag: academy{1nclu51v17y_1of2_f7w_2of2_ce526b3b}

   [SUCCESS] Module 274 (Includes) fully audited and solved: academy{1nclu51v17y_1of2_f7w_2of2_ce526b3b}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{1nclu51v17y_1of2_f7w_2of2_ce526b3b}`
- **Verifikasi API Platform:** Penyerahan token melalui endpoint REST API `POST /api/submissions/` menghasilkan status **HTTP 201 Created**:
  ```json
  {
    "user": 1072359,
    "challenge": 274,
    "flag": "academy{1nclu51v17y_1of2_f7w_2of2_ce526b3b}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Relevansi Modul LKS Cyber Security (Web Application Reconnaissance & Security Auditing):**
  - Peserta kompetisi LKS modul Web Security sering terpaku hanya pada inspeksi tampilan visual atau markup HTML halaman depan.
  - Setiap tautan aset eksternal (CSS, JavaScript, SVG, manifest JSON, berkas sourcemap `.map`) wajib dienumerasi secara sistematis karena kerap menyimpan rahasia konfigurasi API backend, endpoint tersembunyi, atau catatan perbaikan bug.
- **Remediasi & Mitigasi Defensif Komprehensif:**
  1. **Integrasi Pipeline Build Otomatis (Minification & Comment Stripping):**
     Gunakan kakas pemroses build produksi (misalnya Vite, esbuild, Terser, atau Webpack) yang secara otomatis membersihkan seluruh komentar pengembang dan memperkecil ukuran berkas (*minification*) sebelum aset didistribusikan ke server produksi.
  2. **Audit Kode Pra-Rilis (Static Analysis & Secret Scanning):**
     Pasang pemindai rahasia statis (seperti TruffleHog atau GitGuardian) dalam pipeline CI/CD untuk memastikan tidak ada kunci privat, token otorisasi, atau komentar internal yang terdorong ke repositori produksi.
  3. **Penyimpanan Konfigurasi Terpusat:**
     Jangan pernah menanamkan konfigurasi sensitif pada aset klien. Seluruh kredensial wajib disimpan di sisi server via *environment variables* yang terlindungi.
