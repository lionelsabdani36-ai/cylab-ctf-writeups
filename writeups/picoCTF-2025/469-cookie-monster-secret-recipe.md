# Writeup: Cookie Monster Secret Recipe (Challenge ID: 469)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / HTTP State Management & Insecure Sensitive Cookie Storage
- **Difficulty:** Easy (1)
- **Points:** 50
- **Author:** Brhane Giday and Prince Niyonshuti N.
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{c00k1e_m0nster_l0ves_c00kies_1E06422A}`
- **Flag Platform Asli:** `picoCTF{c00k1e_m0nster_l0ves_c00kies_1E06422A}`
- **Flag Komunitas:** `CTF{c00k1e_m0nster_l0ves_c00kies_1E06422A}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Assessment), RFC 6265 (HTTP State Management Mechanism), RFC 9110 (HTTP Semantics), OWASP Top 10 A01:2021 (Broken Access Control) & A04:2021 (Insecure Design), CWE-312 (Cleartext Storage of Sensitive Information), & CWE-319 (Cleartext Transmission of Sensitive Information).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Web Application Security & HTTP State Inspection*:
- **Skenario Tantangan:** Aplikasi web sederhana bertema "Cookie Monster Secret Recipe" mengundang peserta untuk menemukan resep kue rahasia yang tersembunyi pada portal situs web. Form antarmuka menyajikan opsi login yang mengirimkan kredensial ke endpoint `login.php`.
- **Deskripsi Soal:** *"Cookie Monster has hidden his top-secret cookie recipe somewhere on his website. As an aspiring cookie detective, your mission is to uncover this delectable secret. Can you outsmart Cookie Monster and find the hidden recipe? Hints: Sometimes, the most important information is hidden in plain sight. Have you checked all parts of the webpage? Cookies aren't just for eating - they're also used in web technologies! Web browsers often have tools that can help you inspect various aspects of a webpage, including things you can't see directly."*
- **Batasan Lingkungan & Scope Audit:**
  1. Akses web lab on-demand CyLab (`http://host:port/`).
  2. Inspeksi siklus permintaan dan tanggapan HTTP (*request/response cycle*) pada endpoint login maupun beranda.
  3. Pemisahan data visual antarmuka pengguna (HTML DOM) dari metadata transport HTTP (Header Respons).
  4. Dekode format representasi data Base64 dan URL-encoding pada header `Set-Cookie`.
  5. Verifikasi live submission melalui REST API CyLab `POST /api/submissions/` (HTTP Status 201 Created).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Mekanisme Manajemen Status HTTP (RFC 6265 / RFC 9110):**
   Protokol HTTP dirancang secara *stateless*. Untuk mengaitkan serangkaian permintaan ke sesi pengguna yang sama, server menerbitkan header respons:
   `Set-Cookie: <cookie-name>=<cookie-value>; Path=/; ...`
   Setiap peramban web yang mematuhi standar RFC 6265 akan menyimpan nilai cookie tersebut dalam penyimpanan lokal klien (*client-side cookie jar*) dan menyertakannya kembali pada header `Cookie` dalam setiap permintaan berikutnya ke domain terkait.

2. **Akar Kerentanan Penyimpanan Informasi Sensitif di Sisi Klien (CWE-312 / CWE-319):**
   Menyimpan rahasia bisnis, token otorisasi, atau kunci bendera secara langsung pada nilai cookie merupakan kelemahan arsitektur kritis (*Insecure Design* / OWASP A04:2021):
   - Klien memiliki akses kontrol dan visibilitas 100% terhadap seluruh data cookie yang dikirimkan oleh server.
   - Enkoding dua arah (*reversible encoding*) seperti Base64 atau URL-encode bukanlah enkripsi. Skema ini tidak menyediakan kerahasiaan (*confidentiality*) ataupun integritas kriptografis (*integrity*).
   - Pengembang sering kali mengira data cookie tersembunyi karena tidak dirender secara eksplisit pada badan dokumen HTML, padahal DevTools peramban (Network tab / Application tab) maupun utilitas baris perintah (`curl -i`) menampilkan seluruh header HTTP secara transparan.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Header Transport HTTP Menggunakan cURL:**
   Mengirimkan permintaan HTTP GET atau POST ke instance target:
   ```bash
   curl -i -s http://chatelaine.cylabacademy.net:30736/login.php \
        -d "username=guest&password=password"
   ```

2. **Analisis Header Respons Server:**
   Server merespons dengan header respons berikut:
   ```http
   HTTP/1.1 200 OK
   Date: Mon, 26 Oct 2026 16:07:18 GMT
   Server: Apache/2.4.68 (Debian)
   X-Powered-By: PHP/8.3.33
   Set-Cookie: secret_recipe=YWNhZGVteXtjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzXzFFMDY0MjJBfQ%3D%3D; expires=...
   Content-Type: text/html; charset=UTF-8
   ```

3. **Ekstraksi Nilai Cookie & Dekode Base64:**
   Nilai cookie `secret_recipe` mengalami URL-encode pada karakter penutup `%3D%3D` (`==`).
   Melakukan normalisasi dan dekode Base64:
   ```bash
   echo "YWNhZGVteXtjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzXzFFMDY0MjJBfQ==" | base64 -d
   ```
   Hasil dekode menghasilkan teks bendera:
   ```text
   academy{c00k1e_m0nster_l0ves_c00kies_1E06422A}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{c00k1e_m0nster_l0ves_c00kies_1E06422A}`
- **Flag Platform Asli:** `picoCTF{c00k1e_m0nster_l0ves_c00kies_1E06422A}`
- **Status API Verification:** `POST /api/submissions/` mengembalikan respons `HTTP 201 Created` dengan `{"correct": true, "status": "correct"}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Penerapan Arsitektur Sesi Sisi Server (Server-Side Session Pattern):**
   Jangan pernah menyimpan informasi rahasia atau hak akses otorisasi di dalam cookie sisi klien. Simpan informasi sesi pada basis data atau cache memori aman di sisi server (misalnya Redis dengan enkripsi saat istirahat / *encryption at rest*), dan hanya kirimkan token acak bernilai entropi tinggi (128-256 bit UUIDv4/CSPRNG) sebagai identifier sesi kepada klien.

2. **Pemberian Flag Keamanan Cookie Lengkap (Hardened Cookie Attributes):**
   Selalu konfigurasikan atribut keamanan cookie secara ketat:
   - `HttpOnly`: Mencegah skrip peramban (JavaScript DOM) membaca nilai cookie, memitigasi risiko pencurian sesi saat terjadi celah Cross-Site Scripting (XSS).
   - `Secure`: Memastikan transmisi cookie hanya melalui protokol terenkripsi TLS (HTTPS).
   - `SameSite=Strict` atau `SameSite=Lax`: Mencegah peramban menyertakan cookie dalam permintaan lintas situs tanpa otorisasi, memitigasi serangan Cross-Site Request Forgery (CSRF).
