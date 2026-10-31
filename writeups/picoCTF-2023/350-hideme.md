# Writeup: hideme (Challenge ID: 350)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Steganography & File Carving
- **Difficulty:** Medium (diff=2)
- **Event:** picoCTF 2023
- **Flag:** `academy{Hiddinng_An_imag3_within_@n_ima9e_404ff71e}`

---

## Problem Statement & Scope

Tantangan menyediakan file gambar PNG (`flag.png`). Investigasi SOC mendeteksi transfer gambar mencurigakan yang diduga menyembunyikan payload rahasia di dalam struktur biner file.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Polyglot & Appended File Structures (NIST SP 800-115 File Carving):** Format file gambar seperti PNG mengakhiri strukturnya dengan chunk biner `IEND`. Pembaca gambar standar (image viewer) mengabaikan data biner setelah penanda `IEND`.
2. **Embedded ZIP Archive Carving:** Penyerang atau teknik steganografi sering menggabungkan arsip ZIP di akhir file gambar (`cat file.png secret.zip > out.png`). Magic bytes `PK\x03\x04` (`0x50 0x4B 0x03 0x04`) mengindikasikan header ZIP lokal yang dapat diekstrak menggunakan alat carving (`binwalk`, `foremost`) atau modul Python `zipfile`.
3. **Analisis Struktur Offset:** Pada file target, header `PK\x03\x04` ditemukan tepat di offset byte 15929, membungkus direktori `secret/` yang memuat gambar `secret/flag.png`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh artefak: `flag.png` dari CDN CyLab Academy (`challenge-files.cylabacademy.net/library/...`).
2. Deteksi tanda arsip ZIP tersembunyi:
   ```bash
   binwalk flag.png
   # atau menggunakan grep biner:
   grep -a -b -o "PK" flag.png
   ```
3. Ekstraksi arsip ZIP dari offset 15929:
   ```bash
   binwalk -e flag.png
   # Direktori _flag.png.extracted/ memuat secret/flag.png
   ```
4. Ekstraksi teks dari `secret/flag.png` menggunakan OCR (`tesseract`) atau visual inspection.
5. Verifikasi token via REST API: `POST /api/submissions/` dengan payload `{"challenge": 350, "flag": "academy{Hiddinng_An_imag3_within_@n_ima9e_404ff71e}"}` menghasilkan HTTP Status 201 `correct: true`.

---

## Flag & Verifikasi

- **Flag:** `academy{Hiddinng_An_imag3_within_@n_ima9e_404ff71e}`
- **Bukti:** Submisi REST API `/api/submissions/` mengembalikan `{"correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS:** Penguasaan teknik file carving (magic bytes, binwalk, scalpel), pemahaman format kontainer file biner (PNG IEND vs ZIP signature), dan integrasi OCR forensik.
- **Mitigasi Defensif:** Terapkan sanitasi media (re-encoding gambar / stripping metadata & trailing chunks) pada gateway upload file sebelum disimpan atau diteruskan.
