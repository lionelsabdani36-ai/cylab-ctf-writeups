# Writeup: Secret of the Polyglot (Challenge ID: 423)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Polyglot File Analysis
- **Difficulty:** Easy
- **Author:** syreal
- **Event:** picoCTF 2024
- **Points:** 100
- **Flag:** `academy{f1u3n7_1n_pn9_&_pdf_07226ac4}`

---

## Problem Statement & Scope
Pusat Operasi Jaringan (NOC) mendeteksi berkas mencurigakan `flag2of2-final.pdf`. Perangkat pemantau mendeteksi ketidaksesuaian tipe berkas (MIME mismatch), di mana sebagian software membaca berkas sebagai gambar PNG, sementara yang lain membukanya sebagai dokumen PDF.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Konsep Berkas Polyglot:** Berkas polyglot adalah berkas tunggal yang sah dan valid dalam dua atau lebih spesifikasi format berkas yang berbeda secara bersamaan.
2. **Karakteristik Parser PNG & PDF:**
   - **Format PNG:** Mengharuskan magic bytes `89 50 4E 47 0D 0A 1A 0A` di awal berkas (offset 0), dan parser mengabaikan data apa pun yang muncul setelah chunk penutup `IEND`.
   - **Format PDF:** Spesifikasi PDF mengizinkan pembacaan mulai dari penanda `%PDF-` di mana pun sebelum byte ke-1024, dan membaca xref table dari akhir berkas (`%%EOF`).
3. Penyerang menyatukan gambar PNG dan dokumen PDF ke dalam satu berkas biner tanpa merusak sintaks parser masing-masing format.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis tipe berkas menggunakan utilitas `file`:
   ```bash
   file flag2of2-final.pdf
   # Output: PNG image data, 200 x 40, 4-bit colormap, non-interlaced
   ```
2. Ekstraksi visual gambar PNG (bagian awal):
   - Buka dengan image viewer atau potong byte dari awal hingga chunk `IEND`:
   - Lakukan pembacaan teks OCR (tesseract):
   - Bagian 1 terungkap: `academy{f1u3n7_`
3. Dekompresi stream konten PDF (bagian akhir):
   - Cari blok objek PDF `FlateDecode` yang menyimpan teks vektor halaman dokumen:
   - Gunakan Python `zlib.decompress` pada stream PDF obj 5:
   ```text
   (1n_pn9_&_pdf_07226ac4})Tj
   ```
   - Bagian 2 terungkap: `1n_pn9_&_pdf_07226ac4}`
4. Gabungkan kedua fragmen: `academy{f1u3n7_1n_pn9_&_pdf_07226ac4}`.

---

## Flag & Verifikasi
- **Flag:** `academy{f1u3n7_1n_pn9_&_pdf_07226ac4}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Evasi Filter Keamanan Berkas (Antivirus / WAF Evasion):** Berkas polyglot kerap dimanfaatkan malware untuk melewati Content Disarm and Reconstruction (CDR) atau filter ekstensi berkas gateway email.
- **Defensive In-Depth File Validation:** Jangan hanya mengandalkan ekstensi berkas (`.pdf`) atau magic bytes 8-byte pertama. Lakukan verifikasi struktur sintaks berkas secara ketat dan tolak berkas yang memiliki trailing payload di luar pembatas legal (`IEND` untuk PNG, `trailer/%%EOF` untuk PDF).
