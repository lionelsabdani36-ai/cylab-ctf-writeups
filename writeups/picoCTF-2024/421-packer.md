# Writeup: packer (Challenge ID: 421)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Binary Unpacking
- **Difficulty:** Medium (diff=2)
- **Author:** Mubarak Mikail
- **Event:** picoCTF 2024
- **Points:** 100
- **Flag:** `academy{U9X_UnP4ck1N6_B1n4Ri3S_9cb319ae}`

---

## Problem Statement & Scope

Disediakan sebuah berkas biner Linux executable 64-bit bernama `out`. Pengguna diminta melakukan rekayasa balik (*reverse engineering*) terhadap program tersebut untuk memulihkan kode rahasia / flag yang tersembunyi di dalamnya.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kompresi Runtime Executable (UPX Packing):** Biner `out` dikompresi menggunakan *Ultimate Packer for eXecutables* (UPX). Packer menyisipkan stub *decompressor* di awal eksekusi untuk mendekompresi payload asli ke memori sebelum melompat ke *Original Entry Point* (OEP). Header biner ditandai oleh tanda pengenal khas `UPX!` pada tabel segmen.
2. **Kelemahan Obfuscation Ringan (Trivial Packing):** Penggunaan UPX standar tanpa modifikasi algoritma atau proteksi anti-unpacking tidak memberikan perlindungan keamanan yang memadai (*security through obscurity*). Struktur format UPX terdokumentasi penuh dan dapat dikembalikan (*unpacked*) ke bentuk biner ELF murni secara deterministik menggunakan perintah resmi `upx -d`.
3. **Penyimpanan Kredensial Hex-Encoded:** Di dalam biner hasil unpacking, string flag disimpan dalam format hexadecimal literal (`6163616465...`) pada section `.rodata` dan dicetak saat verifikasi password berhasil, sehingga rentan terhadap analisis string statis.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh berkas biner `out` dari pustaka tantangan CyLab Academy:
   ```bash
   curl -s -L https://challenge-files.cylabacademy.net/library/950f65862ed36c218311453c7d58c12ec3ddfb8a78b04ebcd127d3eeb1ea6e11/out -o out
   ```
2. Identifikasi jenis dan status kompresi biner:
   ```bash
   file out
   # ELF 64-bit LSB executable, x86-64, statically linked, no section header
   strings out | grep -i upx
   # $Info: This file is packed with the UPX executable packer http://upx.sf.net $
   ```
3. Lakukan proses dekompresi biner menggunakan UPX CLI:
   ```bash
   upx -d out -o unpacked_out
   # 790574 <- 332044   42.00%   linux/amd64   unpacked_out
   ```
4. Ekstraksi string rahasia dari berkas `unpacked_out`:
   ```bash
   strings unpacked_out | grep -i "flag:"
   # Password correct, please see flag: 61636164656d797b5539585f556e5034636b314e365f42316e34526933535f39636233313961657d
   ```
5. Dekode string heksadesimal ke format ASCII:
   ```python
   bytes.fromhex('61636164656d797b5539585f556e5034636b314e365f42316e34526933535f39636233313961657d').decode()
   # academy{U9X_UnP4ck1N6_B1n4Ri3S_9cb319ae}
   ```
6. Validasi solusi via REST API `POST /api/submissions/` dengan respons status HTTP 201 (`correct: true`).

---

## Flag & Verifikasi

- **Flag:** `academy{U9X_UnP4ck1N6_B1n4Ri3S_9cb319ae}`
- **Bukti Validasi:** Submisi REST API `/api/submissions/` mengembalikan `{"correct": true, "user": 1072359, "challenge": 421}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS:** Pengenalan signature packer biner (UPX headers), teknik automated/manual binary unpacking, serta analisis artefak `.rodata`.
- **Mitigasi Defensif (NIST SP 800-115):** Jangan mengandalkan packer kompresi sebagai mekanisme perlindungan keamanan (*anti-reverse engineering*). Lindungi logika verifikasi dan rahasia aplikasi dengan kontrol integritas berbasis enkripsi end-to-end, proteksi tanda tangan digital biner (code signing), dan validasi otorisasi di sisi backend yang terisolasi.
