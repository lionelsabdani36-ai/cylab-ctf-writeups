# Writeup: CanYouSee (Challenge ID: 408)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / EXIF Metadata Analysis
- **Difficulty:** Easy
- **Author:** Mubarak Mikail
- **Event:** picoCTF 2024
- **Points:** 100
- **Flag:** `academy{ME74D47A_HIDD3N_a81d9431}`

---

## Problem Statement & Scope
Diberikan arsip `unknown.zip` yang memuat citra JPEG resolusi tinggi `ukn_reality.jpg` (4308x2875 piksel). Pengguna diminta mencari data rahasia yang tersembunyi di dalam berkas tersebut.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Metadata Format Gambar (EXIF/XMP):** Berkas gambar format JPEG menyimpan metadata terstruktur dalam segmen header (seperti APP1 untuk EXIF dan XMP). Metadata mencakup informasi kamera, tanggal pembuatan, hak cipta, serta bidang atribusi URL (*Attribution URL*).
2. **Eksfiltrasi via Metadata Lapisan Aplikasi:** Penyerang sering memanfaatkan bidang metadata teks yang sah untuk menyelundupkan muatan data terenkode (Base64) tanpa merusak rendering visual gambar.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Ekstraksi arsip `unknown.zip`:
   ```bash
   unzip unknown.zip
   ```
2. Analisis seluruh field metadata menggunakan `exiftool`:
   ```bash
   exiftool ukn_reality.jpg
   ```
3. Identifikasi field mencurigakan `Attribution URL`:
   ```text
   Attribution URL: YWNhZGVteXtNRTc0RDQ3QV9ISUREM05fYTgxZDk0MzF9Cg==
   ```
4. Dekode string Base64:
   ```bash
   echo "YWNhZGVteXtNRTc0RDQ3QV9ISUREM05fYTgxZDk0MzF9Cg==" | base64 -d
   # Output: academy{ME74D47A_HIDD3N_a81d9431}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{ME74D47A_HIDD3N_a81d9431}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Metadata Sanitization / Stripping:** Sebelum berkas media diunggah ke domain publik atau portal web, implementasikan pipeline pembersihan metadata otomatis (misalnya `exiftool -all= image.jpg` atau integrasi ImageMagick `-strip`).
- **Pencegahan Kebocoran Privasi (OPSEC):** Metadata EXIF asli sering kali memuat koordinat GPS presisi, nomor seri kamera, dan identitas perangkat yang dapat dimanfaatkan penyerang untuk OSINT dan penargetan fisik.
