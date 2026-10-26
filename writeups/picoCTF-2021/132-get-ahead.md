# Writeup: GET aHEAD (Challenge ID: 132)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / HTTP Verbs & Protocol Analysis
- **Difficulty:** Easy
- **Author:** madStacks
- **Event:** picoCTF 2021
- **Points:** 20
- **Flag:** `academy{r3j3ct_th3_du4l1ty_57f62d9}`

---

## Problem Statement & Scope
Disediakan sebuah aplikasi web sederhana dengan dua tombol interaktif: satu tombol mengirimkan request HTTP `GET` yang mewarnai latar belakang menjadi merah, dan tombol lainnya mengirimkan request HTTP `POST` yang mewarnai latar belakang menjadi biru. Peserta diminta mencari cara untuk "get ahead" dan menemukan flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Keberagaman Metode HTTP (HTTP Verbs):** Spesifikasi RFC 7231 mendefinisikan berbagai metode HTTP selain `GET` dan `POST`, termasuk `HEAD`, `OPTIONS`, `PUT`, `DELETE`, `TRACE`, dan `CONNECT`.
2. **Karakteristik Metode HTTP HEAD:** Metode `HEAD` identik dengan `GET`, namun server tidak mengembalikan badan respons (*response body*). Server hanya mengembalikan baris status dan header respons HTTP.
3. **Penyelundupan Informasi dalam Response Header:** Pengembang atau backend aplikasi sering kali menyematkan data diagnostik atau rahasia ke dalam custom header HTTP saat merespons metode selain standar antarmuka web biasa.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis kode sumber formulir pada halaman web:
   ```html
   <form action="index.php" method="GET">
       <input type="submit" value="Choose Red"/>
   </form>
   <form action="index.php" method="POST">
       <input type="submit" value="Choose Blue"/>
   </form>
   ```
2. Mengikuti petunjuk judul soal ("GET aHEAD"), kirimkan permintaan menggunakan metode HTTP `HEAD` ke endpoint `index.php`:
   ```bash
   curl -I http://xebec.cylabacademy.net:11616/index.php
   ```
3. Teliti header respons yang dikembalikan server Apache/PHP:
   ```http
   HTTP/1.1 200 OK
   Date: Mon, 26 Oct 2026 15:08:33 GMT
   Server: Apache/2.4.38 (Debian)
   X-Powered-By: PHP/7.2.34
   flag: academy{r3j3ct_th3_du4l1ty_57f62d9}
   Content-Type: text/html; charset=UTF-8
   ```
4. Header kustom `flag:` menyajikan token flag secara langsung.

---

## Flag & Verifikasi
- **Flag:** `academy{r3j3ct_th3_du4l1ty_57f62d9}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Audit Metode HTTP yang Diizinkan (HTTP Verb Tampering):** Dalam pengerasan web server (modul LKS Linux Server Hardening), batasi metode HTTP yang diizinkan hanya pada metode yang benar-benar digunakan aplikasi (`GET`, `POST`). Gunakan arahan konfigurasi:
  ```apache
  <LimitExcept GET POST>
      Require all denied
  </LimitExcept>
  ```
- **Pembersihan Header Diagnostik:** Pastikan aplikasi produksi tidak mengembalikan header informasi internal atau debug tokens pada respons HTTP. Hapus header seperti `X-Powered-By` dan `Server` untuk meminimalkan paparan fingerprinting infrastruktur.
