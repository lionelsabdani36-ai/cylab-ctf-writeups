# Writeup: Includes (Challenge ID: 274)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Asset Enumeration
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{1nclu51v17y_1of2_f7w_2of2_ce526b3b}`

---

## Problem Statement & Scope
Diberikan sebuah halaman web informatif tentang direktif `include`. Peserta diminta mencari flag yang disembunyikan di antara berkas-berkas eksternal pendukung yang dimuat oleh dokumen HTML utama.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pemisahan Aset Eksternal (External Resource Linking):** Arsitektur web modern memisahkan struktur (HTML), presentasi (CSS), dan perilaku interaktif (JavaScript) ke dalam berkas-berkas terpisah yang dimuat via tag `<link rel="stylesheet">` dan `<script src="...">`.
2. **Komentar Tersembunyi pada Stylesheet & Skrip:** Penyerang atau pengembang yang ceroboh dapat meninggalkan catatan penting di dalam komentar CSS (`/* ... */`) maupun komentar JavaScript (`// ...` atau `/* ... */`). Browser mengunduh aset tersebut secara publik tanpa pembatasan akses.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Akses halaman HTML utama:
   ```bash
   curl -s http://xebec.cylabacademy.net:29636/
   ```
2. Temukan dua berkas referensi aset:
   - `<link rel="stylesheet" href="style.css">`
   - `<script src="script.js"></script>`
3. Ambil isi berkas `style.css`:
   ```bash
   curl -s http://xebec.cylabacademy.net:29636/style.css
   # Output:
   # body {
   #   background-color: lightblue;
   # }
   # /*  academy{1nclu51v17y_1of2_  */
   ```
4. Ambil isi berkas `script.js`:
   ```bash
   curl -s http://xebec.cylabacademy.net:29636/script.js
   # Output:
   # function greetings() { alert("This code is in a separate file!"); }
   # //  f7w_2of2_ce526b3b}
   ```
5. Gabungkan kedua pecahan string menjadi flag utuh:
   $$\text{Part 1} + \text{Part 2} = \text{academy\{1nclu51v17y\_1of2\_f7w\_2of2\_ce526b3b\}}$$

---

## Flag & Verifikasi
- **Flag:** `academy{1nclu51v17y_1of2_f7w_2of2_ce526b3b}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Asset Pipeline Optimization:** Gunakan bundler modern (seperti Webpack, Vite, atau esbuild) yang secara otomatis menghapus seluruh format komentar selama build produksi.
- **Enumerasi Endpoint Lengkap:** Pada pengujian penetrasi aplikasi web LKS, analisis tidak boleh terbatas pada berkas HTML induk saja, melainkan wajib mencakup seluruh aset statis yang direferensikan dalam network tab.
