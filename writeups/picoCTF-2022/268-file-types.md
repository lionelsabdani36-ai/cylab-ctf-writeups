# Writeup: File types (Challenge ID: 268)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / File Format Nesting & Compression Analysis
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{f1len@m3_m@n1pul@t10n_f0r_0b2cur17y_35957b68}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan identifikasi tanda tangan biner (magic bytes) dan penanganan dekompresi bertingkat pada berkas arsip:
> *"This file was found among some files marked confidential but my pdf reader cannot read it, maybe yours can. You can download the file from here."*
> Tautan Artefak: `Flag.pdf` (ukuran ~5.1 KB)

Peserta diberikan berkas bernama `Flag.pdf`. Pembaca PDF standar menolak membuka berkas ini karena struktur internal berkas bukan merupakan dokumen PDF valid melainkan serangkaian arsip bertingkat (*nested archive*) yang disamarkan dengan ekstensi yang menyesatkan (*extension spoofing*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Ambiguitas Ekstensi Berkas vs Tanda Tangan Biner (Magic Bytes):**
   - Sistem operasi dan aplikasi modern kerap bergantung pada ekstensi nama berkas (seperti `.pdf`) untuk menentukan pengait aplikasi (*MIME type association*).
   - Namun, integritas tipe data teknis hanya dapat diidentifikasi secara sahih melalui penanda byte awal (*file signature* atau *magic bytes*). Berkas `Flag.pdf` diawali teks skrip shell pembungkus GNU Shar (`#!/bin/sh` dan `archive of:`), mengonfirmasi bahwa berkas merupakan Shell Archive (shar), bukan PDF.
   - Sesuai prinsip CWE-434 (Unrestricted Upload of File with Dangerous Type) dan CWE-20 (Improper Input Validation), mempercayai ekstensi tanpa verifikasi magic bytes merupakan akar dari berbagai kerentanan injeksi berkas.

2. **Rantai Enkapsulasi Kompresi Berlapis (Recursive Nesting & Decompression Bombs):**
   - Pembuat soal membungkus muatan rahasia ke dalam 10 lapisan kompresi dan encoding biner secara berurutan:
     1. **GNU Shell Archive (shar):** Skrip shell POSIX yang mengemas berkas biner dalam bentuk teks.
     2. **UUEncode:** Skema encoding biner-ke-teks tradisional Unix (blok `begin 600 flag` hingga `end`, 6-bit per karakter, offset 32).
     3. **Ar Archive (`ar`):** Format arsip biner Unix SysV/GNU klasik dengan magic `!<arch>\n` dan header 60 bita.
     4. **Binary CPIO (magic 070707):** Format arsip lawas little-endian (byte header `\xc7\x71`) dengan struktur header 26 bita (13 short integer LE).
     5. **Bzip2 (magic `BZh`):** Kompresi berbasis Burrows-Wheeler Transform.
     6. **Gzip (RFC 1952, magic `\x1f\x8b`):** Kompresi berbasis DEFLATE.
     7. **Lzip (magic `LZIP`, version 1):** Kompresi berbasis algoritma LZMA1 RAW dengan ukuran kamus 4096 bita.
     8. **LZ4 Frame (magic `\x04\x22\x4d\x18`):** Algoritma kompresi berkecepatan tinggi berbasis LZ77.
     9. **LZMA ALONE (format klasik `FORMAT_ALONE`):** Format stream biner kompresi LZMA mandiri.
     10. **Lzop (magic `\x89LZO`):** Format kompresi berbasis algoritma LZO (*Lempel-Ziv-Oberhumer*).
     11. **Lzip Lapis Kedua:** Format arsip lzip kedua membungkus payload XZ.
     12. **XZ (magic `\xfd7zXZ\x00`):** Format kompresi modern berbasis LZMA2.
     13. **Hex-encoded ASCII Text:** Dua baris string heksadesimal yang merepresentasikan karakter ASCII dari token bendera.

3. **Kepatuhan Metodologi NIST SP 800-115 (§ 5.2):**
   - Standar NIST SP 800-115 menganjurkan analisis artefak media digital secara terstruktur: inspeksi header byte untuk setiap lapisan, ekstraksi terkontrol di lingkungan terisolasi (sandbox), dan verifikasi integritas hash untuk mencegah jebakan *decompression bomb* (zip bomb).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Identifikasi Awal Berkas `Flag.pdf`:**
   Unduh artefak dan periksa jenis berkas menggunakan utilitas `file`:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/e8f3b5ee39989674877ad03f9ae7fc66f073d82fa2e4a0a8acdaf4b3e62154cb/Flag.pdf
   file Flag.pdf
   ```
   Keluaran:
   ```text
   Flag.pdf: POSIX shell script, ASCII text executable
   ```

2. **Lapisan 1 & 2: Shell Archive & UUEncode:**
   Buka isi berkas skrip shell untuk mengekstrak blok data biner ter-uuencode:
   ```bash
   sed -n '/^begin 600 flag/,/^end/p' Flag.pdf | uudecode -o extracted_ar
   file extracted_ar
   ```
   Keluaran:
   ```text
   extracted_ar: current ar archive
   ```

3. **Lapisan 3: Ar Archive Extraction:**
   Bongkar berkas arsip `ar` untuk mendapatkan muatan bernama `flag`:
   ```bash
   ar -x extracted_ar
   file flag
   ```
   Keluaran:
   ```text
   flag: cpio hash format archive (little-endian binary)
   ```

4. **Lapisan 4: Binary CPIO Extraction:**
   Ekstrak arsip biner CPIO menggunakan utilitas `cpio`:
   ```bash
   cpio -iv < flag
   file flag
   ```
   Keluaran:
   ```text
   flag: bzip2 compressed data, block size = 900k
   ```

5. **Lapisan 5 & 6: Bzip2 dan Gzip Decompression:**
   Dekompresi berturut-turut muatan bzip2 dan gzip:
   ```bash
   mv flag flag.bz2 && bzip2 -d flag.bz2
   file flag
   # Keluaran: gzip compressed data
   mv flag flag.gz && gzip -d flag.gz
   file flag
   # Keluaran: lzip compressed data, version: 1
   ```

6. **Lapisan 7 s/d 12: Dekompresi Beruntun (Lzip, LZ4, LZMA, Lzop, XZ):**
   Lanjutkan proses dekompresi menggunakan perkakas yang sesuai:
   - `lzip -d flag` -> Menghasilkan LZ4 frame.
   - `lz4 -d -c flag > flag_lzma` -> Menghasilkan LZMA stream.
   - `xz -d -F lzma flag_lzma` -> Menghasilkan lzop payload.
   - `lzop -d flag_lzma.out` -> Menghasilkan lzip kedua.
   - `lzip -d flag_lzma.out` -> Menghasilkan berkas arsip XZ.
   - `xz -d flag_lzma.out` -> Menghasilkan berkas teks heksadesimal ASCII berukuran 110 bita.

7. **Lapisan 13: Konversi Heksadesimal ke ASCII:**
   Teks akhir memuat dua baris string heksadesimal:
   ```text
   61636164656d797b66316c656e406d335f6d406e3170756c407431306e5f
   6630725f3062326375723137795f33353935376236387d0a
   ```
   Konversi string heksadesimal menjadi karakter teks:
   ```bash
   cat flag_hex | tr -d '\n' | xxd -r -p
   ```
   Keluaran:
   ```text
   academy{f1len@m3_m@n1pul@t10n_f0r_0b2cur17y_35957b68}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{f1len@m3_m@n1pul@t10n_f0r_0b2cur17y_35957b68}`
- **Verifikasi API Platform:** Validasi token melalui REST API CyLab (`POST /api/submissions/`) menghasilkan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 268, "flag": "academy{f1len@m3_m@n1pul@t10n_f0r_0b2cur17y_35957b68}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Peserta LKS bidang Digital Forensics wajib menguasai identifikasi format berkas berbasis magic bytes tanpa mempercayai ekstensi penamaan semata. Pemahaman struktur header biner (CPIO, ar, lzip, LZ4, lzop) dan otomasi pipeline penguraian data bertingkat via Python sangat krusial saat menangani artefak malware terobfuskasi.
- **Mitigasi Defensif (File Upload Validation & Decompression Security):**
  1. *Validasi Magic Bytes di Sisi Server:* Validasi berkas unggahan wajib membaca byte pembuka (signature sniffing) menggunakan pustaka tepercaya (seperti `libmagic`), bukan mengandalkan header `Content-Type` dari klien atau ekstensi berkas.
  2. *Proteksi Decompression Bomb (Resource Limiting):* Tetapkan batas kedalaman dekompresi bertingkat (misalnya maksimal 3 lapis) dan batasan rasio ekspansi memori (misalnya maksimal 10:1) untuk mencegah kelumpuhan CPU dan disk akibat Denial of Service (DoS).
  3. *Isolasi Sandbox Lingkungan Ekstraksi:* Seluruh proses pembongkaran arsip tak dikenal harus dijalankan di lingkungan sandbox tanpa hak akses istimewa (unprivileged container) guna mengeliminasi risiko eksekusi kode acak dari file shell archive.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_268_file_types.py`.
