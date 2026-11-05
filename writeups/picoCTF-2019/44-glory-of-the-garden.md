# Writeup: Glory of the Garden (Challenge ID: 44)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Steganographic Data Carving & JPEG File Trailing Analysis
- **Difficulty:** Easy (diff=1)
- **Author:** jedavis/Danny
- **Event:** picoCTF 2019
- **Points:** 50
- **Flag:** `academy{more_than_m33ts_the_3y3ff3b9e86}`

---

## Problem Statement & Scope

Tantangan menyajikan sebuah berkas citra JPEG bernama `garden.jpg`:
> *"This file contains more than it seems. Get the flag from garden.jpg."*
> *Hints: "What is a hex editor?"*

Tujuan modul pembelajaran ini adalah membekali peserta dengan teknik dasar inspeksi artefak biner (*file format specification & artifact analysis*), memahami penanda struktur format berkas grafis (markers), dan mendeteksi data tersembunyi (*trailing payload / overlay data*) yang disisipkan di luar batas resmi spesifikasi berkas.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Spesifikasi Struktur Format JPEG/JFIF (ISO/IEC 10918-1 / ITU-T T.81):**
   - Berkas JPEG tersusun atas penanda heksadesimal (*markers*) berawalan bita `0xFF`:
     - **Start of Image (SOI):** `0xFF 0xD8` pada offset paling awal (`0x00000000`).
     - **Application Marker (APP0/JFIF):** `0xFF 0xE0`.
     - **Define Quantization Table (DQT):** `0xFF 0xDB`.
     - **Start of Frame (SOF0):** `0xFF 0xC0`.
     - **Start of Scan (SOS):** `0xFF 0xDA`.
     - **End of Image (EOI):** `0xFF 0xD9` menandakan akhir resmi dari aliran data citra terkompresi.
   - Pustaka penampil grafis (image viewer / renderer) menghentikan parsing data citra begitu menemukan penanda EOI (`0xFF 0xD9`). Seluruh bita tambahan yang diletakkan setelah penanda EOI diabaikan oleh parser rendering dan tidak mempengaruhi tampilan visual gambar sama sekali.

2. **Mekanisme Steganografi Trailing Data (Overlay Injection / CWE-200):**
   - Penyerang atau perancang tantangan sering menyisipkan muatan teks atau biner di luar batas EOI (*appended overlay data*).
   - Karakteristik ini dimanfaatkan dalam teknik data exfiltration, steganografi sederhana, atau pengemasan file polyglot (misal: penggabungan JPEG dan ZIP).
   - Sesuai panduan NIST SP 800-115 (Artifact Analysis), analis forensik wajib memeriksa kesesuaian antara ukuran fisik berkas pada sistem file (*file system allocation size*) dan ukuran logis yang ditentukan oleh marker akhir berkas (*logical file end marker*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Akuisisi Berkas Artefak:**
   Unduh artefak citra dari repositori pustaka tantangan:
   ```bash
   curl -s -O "https://challenge-files.cylabacademy.net/library/3c60c5a7f7a8067606c51d4b4b3c7913fae709b11e2f2c7adbc0a0b4cda452ff/garden.jpg"
   ```

2. **Inspeksi String Menggunakan Utilitas `strings`:**
   Langkah paling cepat untuk mengekstrak untaian teks printable dari berkas biner tanpa membuka hex editor grafis:
   ```bash
   strings garden.jpg | grep -i "academy"
   ```
   Keluaran:
   ```text
   Here is a flag: academy{more_than_m33ts_the_3y3ff3b9e86}
   ```

3. **Verifikasi Posisi Marker EOI via Hexdump:**
   Untuk memvalidasi akar teknis penempatan flag pada akhir berkas, periksa bagian ekor biner:
   ```bash
   tail -c 100 garden.jpg | xxd
   ```
   Keluaran:
   ```text
   00000000: e8b8 4d38 e483 dbb4 e24f ffd9 4865 7265  ..M8.....O..Here
   00000010: 2069 7320 6120 666c 6167 3a20 6163 6164   is a flag: acad
   00000020: 656d 797b 6d6f 7265 5f74 6861 6e5f 6d33  emy{more_than_m3
   00000030: 3374 735f 7468 655f 3379 3366 6633 6239  3ts_the_3y3ff3b9
   00000040: 6538 367d 0a                             e86}.
   ```
   Dapat diamati dengan jelas bahwa penanda EOI `ff d9` terletak tepat sebelum string ASCII `Here is a flag: ...`.

4. **Ekstraksi Token Flag:**
   Token flag yang diperoleh: `academy{more_than_m33ts_the_3y3ff3b9e86}`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{more_than_m33ts_the_3y3ff3b9e86}`
- **Verifikasi API Platform:** Validasi token melalui endpoint `POST /api/submissions/` berhasil diverifikasi dengan respons:
  ```json
  {"user": 1072359, "challenge": 44, "flag": "academy{more_than_m33ts_the_3y3ff3b9e86}", "correct": true, "historical": false}
  ```
  Status kode HTTP 201 Created mengonfirmasi bahwa flag valid.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Relevansi Kompetensi Forensik LKS:** Pada modul Digital Forensics LKS Cyber Security, verifikasi integritas berkas citra adalah prosedur wajib. Peserta harus terbiasa mendeteksi anomali ukuran (*slack space / file trailer carving*) menggunakan alat CLI seperti `strings`, `binwalk`, `xxd`, maupun `foremost`.
- **Mitigasi Defensif (Application Whitelisting & File Upload Sanitization):**
  - Aplikasi web yang menerima unggahan gambar wajib memvalidasi tidak hanya ekstensi berkas atau magic bytes awal (`0xFF 0xD8`), melainkan juga melakukan *image re-encoding/sanitization* (misalnya menggunakan pustaka Pillow / ImageMagick untuk merender ulang citra dan menyimpannya kembali tanpa data overlay).
  - Penghapusan bita asing di luar penanda EOI secara efektif melenyapkan payload steganografi tersembunyi, skrip webshell yang diselundupkan (*polyglot files*), dan kanal data exfiltration.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_44_glory_of_the_garden.py`.
