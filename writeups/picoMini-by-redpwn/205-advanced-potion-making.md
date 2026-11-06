# Writeup: advanced-potion-making (Challenge ID: 205)

- Platform: CyLab Security Academy (picoCTF)
- Category: Forensics / File Header Carving & Color Plane Steganography
- Difficulty: Medium (diff=2)
- Author: redpwn
- Event: picoMini by redpwn
- Points: 100
- Flag: `picoCTF{w1z4rdry}` (Komunitas: `CTF{w1z4rdry}`)

---

## Problem Statement & Scope

Tantangan menguji teknik perbaikan berkas biner rusak (*corrupted file carving/repair*) dan analisis steganografi bidang warna citra digital:
> *"Ron just found his own copy of advanced potion making, but its been corrupted by some kind of spell. Help him recover it!"*  
>  
> Berkas: `advanced-potion-making`

Lingkup pengujian mencakup inspeksi heksadesimal terhadap byte pembuka berkas (*file magic bytes / file signature*), identifikasi struktur kontainer citra Portable Network Graphics (PNG / RFC 2083), perbaikan field chunk `IHDR` beserta verifikasi checksum CRC-32, serta ekstraksi lapisan steganografi warna monokromatik untuk membaca flag tersembunyi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Spesifikasi Format Citra PNG (RFC 2083 & ISO/IEC 15948):**
   - Berkas PNG wajib diawali dengan tanda tangan 8-byte (*Magic Bytes*):
     $$\text{0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A} \quad (\texttt{"\\x89PNG\\r\\n\\x1a\\n"})$$
   - Tanda tangan ini dirancang untuk mendeteksi galat transmisi FTP/ASCII (`\r\n` dan byte EOF `0x1A`).
   - Chunk pertama wajib berupa `IHDR` (*Image Header*) dengan struktur:
     - 4 byte panjang data (*Length*): Selalu `00 00 00 0D` (13 byte).
     - 4 byte tipe chunk (*Chunk Type*): `49 48 44 52` (`"IHDR"`).
     - 13 byte data: Lebar (4 byte), Tinggi (4 byte), Bit depth (1 byte), Color type (1 byte), Compression (1 byte), Filter method (1 byte), Interlace method (1 byte).
     - 4 byte CRC-32: Dihitung atas tipe chunk dan data chunk.

2. **Analisis Kerusakan Biner (File Corruption Analysis):**
   - Inspeksi biner awal pada berkas target menunjukkan kerusakan pada 6 byte pertama:
     ```text
     Berkas Asli:    89 50 42 11 0d 0a 1a 0a 00 12 13 14 49 48 44 52 ...
     Standar PNG:    89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 ...
     ```
   - Byte offset 2 dan 3 (`42 11`) merusak tanda tangan PNG.
   - Byte offset 8 hingga 11 (`00 12 13 14`) merusak panjang chunk `IHDR`.
   - Menariknya, CRC yang tercantum pada berkas (`04 2d e7 78`) cocok persis dengan CRC-32 dari chunk `IHDR` 13-byte asli, membuktikan dimensi gambar ($2448 \times 1240$) dan parameter warna tidak dimanipulasi.

3. **Steganografi Bidang Warna (Visual Plane Steganography):**
   - Setelah berkas diperbaiki dan dibuka, citra tampak sebagai kanvas merah solid (*solid red image*).
   - Penyerang menyembunyikan teks dengan memodifikasi variasi intensitas piksel yang sangat halus (*subtle RGB differences*) pada saluran warna. Konversi ke hitam-putih (*thresholding* binarisasi) memisahkan teks kontras dari latar belakang.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Awal Byte Biner:**
   Menggunakan Python untuk memeriksa heksadesimal 32 byte pertama:
   ```python
   with open('advanced-potion-making', 'rb') as f:
       print(f.read(32).hex(' '))
   # 89 50 42 11 0d 0a 1a 0a 00 12 13 14 49 48 44 52 ...
   ```

2. **Perbaikan Header Menggunakan Python:**
   Memperbaiki tanda tangan PNG dan field panjang chunk `IHDR`:
   ```python
   raw = bytearray(open('advanced-potion-making', 'rb').read())
   raw[0:8] = b'\x89PNG\r\n\x1a\n'
   raw[8:12] = b'\x00\x00\x00\r'
   open('repaired.png', 'wb').write(raw)
   ```

3. **Verifikasi Integritas dan Binarisasi Citra:**
   Membuka berkas `repaired.png` menggunakan library Pillow/GIMP.
   Citra berukuran $2448 \times 1240$ piksel.
   Dengan menerapkan filter desaturasi / konversi Black & White (atau inspeksi bitplane LSB Red/Green via Aperi'Solve/zsteg), teks tersembunyi muncul dengan jelas:
   ```text
   picoCTF{w1z4rdry}
   ```

4. **Verifikasi Skrip Solusi:**
   Skrip otomasi dieksekusi melalui `scripts/solve_205_advanced_potion_making.py`:
   ```bash
   python3 scripts/solve_205_advanced_potion_making.py
   # Luaran: picoCTF{w1z4rdry}
   ```

---

## Flag & Verifikasi

- **Flag:** `picoCTF{w1z4rdry}`
- **Komunitas:** `CTF{w1z4rdry}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 205, "flag": "picoCTF{w1z4rdry}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi Forensik File Carving pada LKS Cyber Security:**
   - Soal forensik tingkat LKS Nasional sering menyajikan berkas dengan header yang sengaja dirusak (*tampered magic numbers*) atau chunk metadata yang tidak sinkron.
   - Analis forensik harus hafal struktur dasar spesifikasi file container populer (PNG, JPEG, PDF, ZIP/ELF) dan mampu merekonstruksi berkas menggunakan hex editor atau skrip Python tanpa ketergantungan pada automated GUI tools.

2. **Rekomendasi Integritas Berkas Digital (Remediation & Hardening):**
   - **Validasi Header & Format Ketat pada Input Handling:** Layanan web penerima berkas harus memvalidasi magic bytes dan melakukan parsing struktur chunk secara mendalam (*strict format parsing*) sebelum memproses berkas citra.
   - **Sanitasi dan Rekompresi Citra (Image Normalization):** Bersihkan artefak steganografi dengan cara me-render ulang (*re-encoding*) citra yang diunggah pengguna ke format baru di sisi server, menghapus variasi LSB dan saluran warna tersembunyi.
