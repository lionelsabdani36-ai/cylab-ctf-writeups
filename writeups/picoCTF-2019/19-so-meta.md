# Writeup: So Meta (Challenge ID: 19)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Image Metadata Extraction
- **Difficulty:** Medium
- **Author:** Danny
- **Event:** picoCTF 2019
- **Points:** 150
- **Flag:** `academy{s0_m3ta_d4aa0408}`

---

## Problem Statement & Scope
Diberikan sebuah berkas gambar PNG bernama `pico_img.png`. Analis forensik diminta untuk mengidentifikasi keberadaan token rahasia (flag) yang disematkan di dalam berkas tanpa merusak integritas visual gambar.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Struktur Metadata Format PNG:** Berkas Portable Network Graphics (PNG) tersusun atas rangkaian chunk data terstruktur, antara lain IHDR (Image Header), IDAT (Image Data), IEND (Image End), serta chunk metadata tekstual opsional seperti `tEXt`, `zTXt`, dan `iTXt` (International Textual Data).
2. **Kelemahan Penyimpanan Data Sensitif pada Header Grafis:** Seringkali pengembang atau pengguna awam menyematkan informasi komentar, copyright, deskripsi internal, atau data audit di dalam metadata gambar tanpa menyadari bahwa metadata tersebut dapat dibaca secara langsung tanpa perlu melakukan proses rendering piksel.
3. **Analisis String & Header Carving:** Berkas biner yang memuat teks ASCII atau UTF-8 di segmen metadata dapat diekstraksi menggunakan pencarian pola string langsung (`strings`) atau pembacaan EXIF/chunk metadata parser.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh berkas gambar tantangan:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/7d12ed78e80c80afccae7ae860ed2277f044812e86c7267efbf7e0200fc9fd1e/pico_img.png
   ```
2. Lakukan inspeksi metadata menggunakan `strings` dan filter pola flag:
   ```bash
   strings pico_img.png | grep -E "academy\{|picoCTF\{"
   # Output: academy{s0_m3ta_d4aa0408}
   ```
3. Alternatif menggunakan `exiftool`:
   ```bash
   exiftool pico_img.png | grep -i "Comment\|Artist"
   ```
4. Eksekusi solver python terintegrasi:
   ```bash
   python3 scripts/solve_19_so_meta.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{s0_m3ta_d4aa0408}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pembersihan Metadata (Metadata Sanitization):** Dalam arsitektur web dan sistem pertahanan data (LKS Defensive), setiap berkas publik atau unggahan pengguna wajib melalui proses *metadata stripping* (misal menggunakan modul ImageMagick `-strip` atau library Pillow) sebelum didistribusikan ke CDN publik.
- **Deteksi Data Leakage Forensik:** Tim blue team wajib memonitor lalu lintas data egress untuk memastikan tidak ada artefak metadata internal yang membocorkan kredensial atau topologi sistem.
