# Writeup: hideme (Challenge ID: 350)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / File Carving & Appended PKZIP Polyglot (CWE-434 / CWE-200)
- **Difficulty:** Medium (diff=2)
- **Event:** picoCTF 2023
- **Points:** 100
- **Author:** Mubarak Mikail
- **Flag Resmi:** `academy{Hiddinng_An_imag3_within_@n_ima9e_404ff71e}`
- **Standar Audit:** NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Verification)

---

## Problem Statement & Scope

Tantangan `hideme` menyediakan berkas gambar PNG bernama `flag.png`. Skenario investigasi forensik digital mencatat bahwa analis SOC mendeteksi transfer berkas gambar yang dicurigai membawa data rahasia terselubung di antara dua entitas. Peserta ditugaskan melakukan audit struktur biner gambar untuk mengungkap dan mengekstrak muatan tersembunyi yang disisipkan tanpa merusak validitas visual berkas saat dibuka pada aplikasi peramban standar.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Kontainer PNG & Batas Chunk (ISO/IEC 15948:2004 / RFC 2083):**
   Spesifikasi berkas Portable Network Graphics (PNG) diawali oleh 8-byte magic header `\x89PNG\r\n\x1a\n` (`89 50 4E 47 0D 0A 1A 0A`) dan tersusun atas serangkaian blok data (*chunks*), seperti `IHDR`, `IDAT`, dan diakhiri secara definitif oleh chunk penutup `IEND` (`\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82`).
   
   Sebagian besar penampil gambar (image viewer) dan parser grafis hanya memproses byte hingga chunk `IEND` dan secara pasif mengabaikan data biner tambahan (*trailing bytes*) yang disematkan setelahnya. Karakteristik ini membuka peluang teknik steganografi berkas bertumpuk (*polyglot / appended file steganography*).

2. **Penyisipan Kontainer PKZIP (CWE-434 / CWE-200):**
   Analisis penelusuran heksadesimal terhadap byte di luar chunk `IEND` pada offset 15.929 (`0x3E39`) menemukan signature lokal arsip PKZIP:
   `PK\x03\x04` (`50 4B 03 04`).
   
   Penyerang menggabungkan berkas arsip terkompresi ke akhir berkas PNG valid (misalnya melalui perintah `cat secret.zip >> flag.png`). Arsip ini menyimpan struktur direktori `secret/` yang memuat berkas gambar rahasia `secret/flag.png` berukuran 5.517 byte.

3. **Ekstraksi Forensik & Rekonstruksi Visual:**
   Karena struktur ZIP tidak mengalami korupsi atau enkripsi sandi, pemotongan (*carving*) byte stream mulai dari offset `0x3E39` hingga akhir berkas memungkinkan dekompresi artefak secara murni. Berkas grafis di dalamnya kemudian diproses melalui *Optical Character Recognition* (OCR) atau inspeksi visual untuk memulihkan token autentik.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Signature dan Deteksi Trailer:**
   Periksa informasi chunk PNG dan cari penanda signature tersembunyi:
   ```bash
   file flag.png
   # Output: PNG image data, 512 x 512, 8-bit/color RGBA, non-interlaced
   
   # Deteksi keberadaan container ZIP via binwalk atau hexdump:
   binwalk flag.png
   # DECIMAL       HEXADECIMAL     DESCRIPTION
   # --------------------------------------------------------------------------------
   # 0             0x0             PNG image, 512 x 512, 8-bit/color RGBA, non-interlaced
   # 15929         0x3E39          Zip archive data, at least v2.0 to extract, compressed size: 5517
   ```

2. **Ekstraksi Artefak Tersembunyi (File Carving):**
   Gunakan `binwalk` atau pemotongan biner berbasis Python:
   ```bash
   binwalk -e flag.png
   # Menghasilkan direktori _flag.png.extracted/ memuat secret/flag.png
   ```

3. **Pemulihan Token via OCR / Visual Inspection:**
   Jalankan utilitas OCR baris perintah `tesseract` atau buka berkas `secret/flag.png`:
   ```bash
   tesseract _flag.png.extracted/secret/flag.png stdout --psm 6
   # Output: academy{Hiddinng_An_imag3_within_@n_ima9e_404ff71e}
   ```

4. **Verifikasi Token Live CyLab REST API:**
   Kirim token hasil ekstraksi ke endpoint validasi resmi platform:
   ```bash
   curl -X POST https://learn.cylabacademy.org/api/submissions/ \
     -H "Content-Type: application/json" \
     -H "X-CSRFToken: <CSRF_TOKEN>" \
     -H "Cookie: sessionid=<SESSION_ID>; csrftoken=<CSRF_TOKEN>" \
     -d '{"challenge": 350, "flag": "academy{Hiddinng_An_imag3_within_@n_ima9e_404ff71e}"}'
   ```
   Server mengembalikan status HTTP 201 Created dengan atribut `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{Hiddinng_An_imag3_within_@n_ima9e_404ff71e}`
- **Status Submisi REST API:** HTTP 201 Created (`correct: true`, `historical: false`).
- **Skrip Reproduktif:** `scripts/solve_350_hideme.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Silabus LKS Cyber Security:**
   - Modul Digital Forensics: Pengenalan struktur file biner (PNG IEND vs PKZIP magic bytes), analisis artefak steganografi, dan penggunaan otomasi scripting Python untuk file carving deterministik.
   - Analisis Malicious Document: Membedakan data gambar murni dari teknik *polyglot file delivery* yang sering dipakai malware untuk menyembunyikan payload tahap kedua.

2. **Mitigasi Defensif (Hardening & File Sanitization):**
   - **Content Disarm and Reconstruction (CDR):** Gateway unggah berkas wajib melakukan re-encoding gambar (misalnya membuka via pustaka grafis server dan menyimpannya ulang sebagai PNG baru) guna membuang seluruh trailing data dan chunk non-standar.
   - **Strict File Boundary Validation:** Sistem validasi unggahan harus memeriksa ukuran berkas total terhadap batas chunk akhir (`IEND` + 12 byte) dan menolak berkas yang memiliki byte residu tak terdefinisi.
