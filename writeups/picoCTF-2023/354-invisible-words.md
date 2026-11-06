# Writeup: Invisible WORDs (Challenge ID: 354)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics
- **Difficulty:** Hard
- **Event:** picoCTF 2023
- **Author:** LT 'syreal' Jones
- **Flag:** `academy{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_75527d56}`

---

## Problem Statement & Scope

Tantangan memberikan sebuah file gambar `output.bmp` berukuran 2.073.738 byte (resolusi $960 \times 540$ piksel, kedalaman warna 32-bit per piksel). Deskripsi soal memberikan petunjuk terkait kata "WORDs" (mengacu pada tipe data 16-bit dalam arsitektur komputer) serta anomali kualitas visual pada gambar.

Tujuan analisis adalah membongkar skema steganografi saluran warna, memulihkan file arsip tersembunyi yang disisipkan di antara data raster gambar, dan mengekstrak flag resmi kompetisi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Format File BMP 32-bit (BGRA Color Model):**
   - File BMP dengan kedalaman 32-bit menyimpan data piksel dalam blok 4 byte: Blue (1 byte), Green (1 byte), Red (1 byte), dan Alpha/Reserved (1 byte).
   - Dua byte pertama (Blue + Green) membentuk satu 16-bit integer (WORD dalam terminologi x86/Win32).
2. **Steganografi Interleaving 16-bit WORD:**
   - Pembuat soal menyisipkan aliran file terkompresi ZIP dengan membagi aliran byte target ke dalam chunk 2 byte (WORD) dan menyisipkannya bergantian (*interleaved*) ke dalam saluran Blue + Green setiap piksel.
   - Saluran Red dan Alpha dipertahankan untuk memelihara gradasi visual penyamaran cover image.
   - File arsip ZIP dimulai pada offset `0x8c` dengan signature `PK\x03\x04` dan diakhiri dengan record *End of Central Directory* (EOCD, `PK\x05\x06`).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Header & Deteksi Magic Bytes:**
   - Memeriksa struktur header BMP: offset piksel berada di `0x8a`.
   - Pemeriksaan byte heksadesimal pada offset `0x8c` menemukan pecahan magic number ZIP: `50 4B` (`PK`), diikuti 2 byte cover `95 52`, kemudian `03 04`, diikuti 2 byte cover `C6 18`.
2. **Ekstraksi Data WORD & Rekonstruksi Arsip:**
   - Membaca file mulai dari offset `0x8c` dengan pola: ambil 2 byte (WORD payload), lewati 2 byte (WORD cover).
   - Menghasilkan aliran byte biner yang diawali oleh header valid ZIP `PK\x03\x04`.
   - Mengidentifikasi record EOCD (`PK\x05\x06`) di offset byte ke-169.574 untuk memotong sisa padding piksel yang tidak terpakai sehingga parser ZIP tidak mendeteksi galat korupsi struktur.
3. **Dekompresi & Pencarian Flag:**
   - Arsip yang dipulihkan memuat file teks `ZnJhbmtlbnN0ZWluLXRlc3QudHh0` (naskah novel *Frankenstein* karya Mary Shelley).
   - Melakukan ekstraksi teks dan pencarian pola regex `academy{[^}]+}`:
     ```text
     academy{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_75527d56}
     ```
4. **Verifikasi Flag:**
   - Mengirimkan token ke REST API CyLab `POST /api/submissions/`.

---

## Flag & Verifikasi

- **Flag:** `academy{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_75527d56}`
- **Bukti Validasi:** REST API CyLab merespons dengan HTTP Status 201 Created:
  ```json
  {"user": 1072359, "challenge": 354, "flag": "academy{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_75527d56}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Deteksi Saluran Tersembunyi (Steganalysis):** Modulasi bit atau byte pada kanal warna tertentu (Blue/Green channel noise) dapat dideteksi menggunakan analisis entropi saluran (*channel-split entropy analysis*) dan deteksi diskontinuitas statistik gradien warna.
- **Data Loss Prevention (DLP) & File Sanitization:** Sistem pengawasan jaringan defensif harus menerapkan *Content Disarm and Reconstruction* (CDR) pada file media grafis guna membersihkan saluran bit rendah atau anomali saluran warna sebelum file diizinkan melewati perimeter keamanan.
