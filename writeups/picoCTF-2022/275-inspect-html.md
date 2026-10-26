# Writeup: Inspect HTML (Challenge ID: 275)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Source Code Reconnaissance
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{1n5p3t0r_0f_h7ml_cdc35adf}`

---

## Problem Statement & Scope
Disediakan sebuah halaman web statis yang memuat cuplikan teks sejarah kuno tentang tokoh Histiaeus. Peserta diminta memanfaatkan alat inspeksi browser untuk menemukan flag yang tertinggal.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **HTML Comment Exposure:** Sintaks komentar HTML (`<!-- ... -->`) dirancang semata-mata untuk dokumentasi pengembang selama tahap penulisan kode. Browser web mengunduh seluruh teks komentar dan menyediakannya di pohon DOM (*Document Object Model*), meskipun teks tersebut tidak dirender secara visual di viewport.
2. **Ketiadaan Kompilasi Server-Side:** Berkas HTML statis dikirimkan apa adanya (*verbatim*) oleh server web HTTP tanpa proses pemfilteran komentar kecuali jika dikonfigurasi melalui modul web server (seperti `mod_pagespeed` pada Apache atau filter Nginx).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Akses halaman instance target via `curl`:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:14736/
   ```
2. Teliti bagian bawah kode markup sebelum penutup tag `</body>`:
   ```html
     <br>
     <p> Source: Wikipedia on Histiaeus </p>
     <!--academy{1n5p3t0r_0f_h7ml_cdc35adf}-->
   </body>
   </html>
   ```
3. Ekstraksi token flag menggunakan regex:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:14736/ | grep -o "academy{[^}]*}"
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{1n5p3t0r_0f_h7ml_cdc35adf}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Stripping Komentar pada Tahap Produksi:** Otomatisasi proses deployment aplikasi web harus mencakup langkah HTML minification dan comment stripping untuk mencegah bocornya informasi infrastruktur (catatan bug, path direktori internal, kredensial sementara).
- **Inspeksi Kode Sumber (Web Security Assessment):** Dalam kompetisi LKS modul Web Application Security, selalu jadikan penelusuran komentar HTML/JS sebagai langkah pengintaian (*reconnaissance*) pertama.
