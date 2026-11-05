# Writeup: extensions (Challenge ID: 52)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / File Signature & Magic Bytes Analysis
- **Difficulty:** Medium (diff=2)
- **Author:** Sanjay C/Danny
- **Event:** picoCTF 2019
- **Points:** 150
- **Flag:** `academy{now_you_know_about_extensions}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman forensik mengenai tanda tangan berkas (*file signatures / magic bytes*) versus ekstensi berkas visual (*file extensions*):
> *"This is a really weird text file. Can you find the flag? Get the flag from TXT."*

Peserta diberikan tautan unduhan berkas bernama `flag.txt`. Namun, saat berkas tersebut dibuka menggunakan editor teks biasa, berkas menampilkan deretan bita biner yang korup dan tidak terbaca.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Konsep Tanda Tangan Berkas (*Magic Bytes*) vs Ekstensi:**
   - Ekstensi berkas (seperti `.txt`, `.png`, `.pdf`) hanyalah konvensi penamaan pada sistem operasi pengguna untuk menentukan asosiasi aplikasi default. Ekstensi berkas tidak menjamin konten sebenarnya dari berkas tersebut.
   - Sistem operasi berbasis UNIX/Linux dan mesin analisis forensik mengidentifikasi tipe berkas riil berdasarkan byte pembuka unik pada header berkas (*magic numbers / magic bytes*).
   - Berdasarkan spesifikasi RFC 2083 dan ISO/IEC 15948:2004 (*Portable Network Graphics*), berkas PNG wajib diawali oleh 8 bita tanda tangan heksadesimal standar:
     ```text
     89 50 4E 47 0D 0A 1A 0A
     ```
     diikuti oleh blok chunk pertama `IHDR` (`49 48 44 52`).

2. **Ketergantungan Ekstensi Semata pada Validasi Input (CWE-646 & CWE-434):**
   - Kerentanan arsitektural ini merujuk pada CWE-646 (*Reliance on File Name or Extension of Externally-Supplied File*) dan CWE-434 (*Unrestricted Upload of File with Dangerous Type*).
   - Apabila aplikasi web atau pemindai konten hanya memeriksa ekstensi string (misal mengecek apakah nama berkas berakhiran `.txt`), penyerang dapat menyamarkan berkas biner berbahaya (seperti skrip webshell, berkas eksekusi, atau malware) sebagai berkas teks biasa.

3. **Metodologi Forensik NIST SP 800-115:**
   - Standar NIST SP 800-115 (Section 5.3: *Artifact Analysis & Verification*) menetapkan bahwa pemeriksaan integritas berkas harus selalu memvalidasi kesesuaian antara tipe MIME/magic bytes aktual dengan metadata berkas.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak Berkas:**
   Unduh artefak `flag.txt` dari server repositori CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/a5d365fedad883763fb28c78e25a1765220bef6501848c84f2a7a7adf74d83cd/flag.txt
   ```

2. **Inspeksi Header dan Magic Bytes:**
   Jalankan utilitas `file` untuk membaca header biner:
   ```bash
   file flag.txt
   ```
   Keluaran:
   ```text
   flag.txt: PNG image data, 1697 x 608, 8-bit/color RGB, non-interlaced
   ```
   Inspeksi heksadesimal menggunakan `xxd` atau `hexdump`:
   ```bash
   head -c 16 flag.txt | xxd
   ```
   Keluaran:
   ```text
   00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
   ```
   Bita `89 50 4E 47` (`.PNG`) secara definitif mengonfirmasi bahwa berkas ini adalah gambar PNG.

3. **Restorasi Ekstensi dan Ekstraksi Flag:**
   Ubah ekstensi berkas menjadi `.png`:
   ```bash
   mv flag.txt flag.png
   ```
   Ekstrak teks visual dari gambar menggunakan mesin OCR Tesseract atau penampil gambar:
   ```bash
   tesseract flag.png stdout --oem 1
   ```
   Keluaran OCR:
   ```text
   academy{now_you_know_about_extensions}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{now_you_know_about_extensions}`
- **Verifikasi API Platform:** Validasi token melalui endpoint `POST /api/submissions/` menghasilkan respons sukses:
  ```json
  {"user": 1072359, "challenge": 52, "flag": "academy{now_you_know_about_extensions}", "correct": true, "historical": false}
  ```
  Status kode HTTP 201 Created mengonfirmasi keabsahan token.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Dalam modul *Digital Forensics* dan *Web Penetration Testing* LKS Cyber Security, manipulasi ekstensi dan penyamaran tipe berkas merupakan teknik umum. Peserta harus terbiasa menggunakan perkakas `file`, `binwalk`, `xxd`, serta memahami struktur header format media populer (PNG, JPEG, GIF, PDF, ZIP, ELF).
- **Mitigasi Defensif (Strict File Content Validation):**
  1. *Magic Byte Sniffing:* Jangan pernah mempercayai header `Content-Type` yang dikirim klien atau ekstensi nama berkas. Validasi selalu bita tanda tangan awal menggunakan pustaka seperti `libmagic` (pada Linux) atau `file-type` pada backend server.
  2. *Re-encoding / Content Sanitization:* Untuk sistem unggah berkas media, lakukan decoding dan encoding ulang (*re-rendering*) gambar melalui pustaka grafis resmi sebelum disimpan ke penyimpanan persisten guna membersihkan payload tersembunyi.
  3. *Secure Storage:* Simpan berkas hasil unggahan pengguna di luar *web root* atau pada bucket objek terisolasi (*cloud object storage*) dengan header `Content-Disposition: attachment` dan nonaktifkan eksekusi skrip.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_52_extensions.py`.
