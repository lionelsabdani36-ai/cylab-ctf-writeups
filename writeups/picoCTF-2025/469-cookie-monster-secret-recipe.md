# Writeup: Cookie Monster Secret Recipe (Challenge ID: 469)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / HTTP State Management & Response Header Inspection
- **Difficulty:** Easy
- **Author:** picoCTF Team
- **Event:** picoCTF 2025
- **Points:** 50
- **Flag:** `academy{c00k1e_m0nster_l0ves_c00kies_1E06422A}`

---

## Problem Statement & Scope
Aplikasi web sederhana menyajikan portal login "Cookie Monster's Secret Recipe" di mana pengguna diminta menemukan resep kue rahasia. Form login mengirimkan kredensial ke `login.php`. Tantangan ini menguji kemampuan inspeksi mekanisme status sesi HTTP dan header respons server yang tidak terlihat secara langsung pada tampilan render peramban.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **HTTP State Management & Set-Cookie Mechanism (RFC 6265):**
   Protokol HTTP bersifat *stateless*. Server mengelola sesi pengguna dengan mengirimkan header `Set-Cookie: <name>=<value>; Path=/; ...` dalam respons HTTP. Peramban web kemudian menyimpan nilai tersebut dan mengirimkannya kembali pada header `Cookie` di permintaan berikutnya.
2. **Ekspos Data Sensitif dalam Cookie Tanpa Proteksi (Information Disclosure):**
   Menyimpan data rahasia atau flag langsung ke dalam nilai cookie (meskipun di-encode menggunakan Base64 atau URL-encoding) merupakan kerentanan *Sensitive Data Exposure*. Klien memiliki kendali penuh atas inspeksi penyimpanan cookie lokal, sehingga skema enkoding dua arah dapat dibalik dengan mudah.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Luncurkan instance lab web container:
   `PUT /api/challenges/469/instance/`
2. Kirim permintaan POST ke endpoint autentikasi `login.php` dengan data uji sembarang:
   ```bash
   curl -i -X POST http://chatelaine.cylabacademy.net:30736/login.php \
        -d "username=guest&password=password"
   ```
3. Periksa header respons HTTP dari server:
   ```http
   HTTP/1.1 200 OK
   Date: Mon, 26 Oct 2026 16:07:18 GMT
   Server: Apache/2.4.68 (Debian)
   X-Powered-By: PHP/8.3.33
   Set-Cookie: secret_recipe=YWNhZGVteXtjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzXzFFMDY0MjJBfQ%3D%3D; expires=...
   ```
4. Lakukan dekode URL dan dekode Base64 pada nilai cookie `secret_recipe`:
   ```bash
   echo "YWNhZGVteXtjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzXzFFMDY0MjJBfQ==" | base64 -d
   # Output: academy{c00k1e_m0nster_l0ves_c00kies_1E06422A}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{c00k1e_m0nster_l0ves_c00kies_1E06422A}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Larangan Penyimpanan Informasi Rahasia pada Cookie Klien:** Jangan pernah menempatkan token sensitif, kata sandi, atau data otorisasi murni pada cookie peramban. Gunakan token sesi acak dengan entropi tinggi (*cryptographically secure session ID*) yang dipetakan ke penyimpanan sesi aman di sisi server (*server-side session store* seperti Redis atau basis data).
- **Penerapan Atribut Keamanan Cookie:** Selalu tetapkan atribut `HttpOnly` (untuk mencegah pencurian sesi melalui serangan XSS), `Secure` (memastikan transmisi hanya melalui kanal TLS/HTTPS), dan `SameSite=Strict` atau `Lax` (untuk mitigasi Cross-Site Request Forgery / CSRF).
