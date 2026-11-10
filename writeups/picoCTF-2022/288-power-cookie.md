# Writeup: Power Cookie (Challenge ID: 288)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation
- **Difficulty:** Medium (Tier 2)
- **Event:** picoCTF 2022
- **Author:** LT 'syreal' Jones
- **Points:** 200
- **Flag:** `academy{gr4d3_A_c00k13_6cf86b5a}`

---

## Problem Statement & Scope

Aplikasi web Online Gradebook menyediakan opsi akses tamu melalui tombol "Continue as guest". Saat tombol ditekan, skrip sisi klien `guest.js` dieksekusi untuk menyetel cookie status pengguna dan melakukan pengalihan peramban ke endpoint verifikasi hak akses:

```javascript
window.location.href = '/check.php';
document.cookie = "isAdmin=0";
```

Peserta ditugaskan untuk mengaudit mekanisme verifikasi otorisasi pada endpoint `/check.php` dan memperoleh akses administratif untuk membaca token bendera rahasia.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Client-Controlled State & Insecure Direct Cookie Authorization (CWE-565):**
   Aplikasi backend `check.php` mengandalkan nilai mentah dari header HTTP `Cookie` (`isAdmin`) untuk membedakan antara pengguna biasa (tamu) dan administrator tanpa validasi integritas kriptografis (HMAC/tanda tangan digital) atau verifikasi sesi di sisi server.
2. **Improper Authentication & Authorization Bypass (CWE-287 / NIST SP 800-115 § 4.2):**
   Tidak adanya session identifier acak yang tersimpan dalam basis data atau memory cache (misalnya Redis) menyebabkan model otorisasi sepenuhnya bergantung pada input pengguna yang dapat dimanipulasi secara bebas.
3. **Loose Type Evaluation / Boolean Coercion:**
   Backend PHP mengevaluasi nilai parameter cookie secara longgar (`$_COOKIE['isAdmin'] == 1` atau evaluasi truthy), sehingga injeksi string `1` langsung meloloskan cabang kontrol hak akses administrator.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Reconnaissance Aset Sisi Klien:**
   Mengirimkan permintaan HTTP GET ke root aplikasi `/` dan menganalisis berkas JavaScript statis `/guest.js`. Ditemukan bahwa status peran tamu dikonfigurasi melalui manipulasi objek DOM `document.cookie = "isAdmin=0"`.
2. **Inspeksi Respons Baseline Endpoint Otorisasi:**
   Mengirimkan permintaan ke `/check.php` dengan menyertakan header `Cookie: isAdmin=0`. Server memberikan respons teks penolakan: `We apologize, but we have no guest services at the moment`.
3. **Eskalasi Parameter Hak Akses (Cookie Tampering):**
   Mengubah nilai header cookie menjadi `isAdmin=1` dan mengirimkan ulang permintaan HTTP GET ke `/check.php`:
   ```bash
   curl -s -H "Cookie: isAdmin=1" http://<target-instance>/check.php
   ```
4. **Ekstraksi Token Bendera:**
   Server merespons dengan konten rahasia administratif yang memuat token bendera resmi:
   `academy{gr4d3_A_c00k13_6cf86b5a}`.
5. **Otomasi Skrip Reproduktif:**
   Mengimplementasikan skrip reproduktif mandiri pada `scripts/solve_288_power_cookie.py` yang memvalidasi eksploitasi live maupun simulasi deterministik dan menyerahkan token ke REST API CyLab.

---

## Flag & Verifikasi

- **Native Platform Flag:** `picoCTF{gr4d3_A_c00k13_6cf86b5a}`
- **CyLab Accepted Flag:** `academy{gr4d3_A_c00k13_6cf86b5a}`
- **Status Submisi REST API:** HTTP 201 Created (`correct: true`, user `1072359`, challenge 288).

Bukti respons live CyLab API:
```json
{
  "user": 1072359,
  "challenge": 288,
  "flag": "academy{gr4d3_A_c00k13_6cf86b5a}",
  "correct": true,
  "historical": false
}
```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Prinsip Zero-Trust pada Header Klien:**
   Dalam arsitektur web modern, cookie yang dikirim oleh peramban harus diperlakukan sebagai input yang tidak tepercaya (untrusted input). Jangan pernah menyimpan flag status peran (`role`, `isAdmin`, `is_superadmin`) dalam bentuk teks polos di sisi klien.
2. **Implementasi Sesi Sisi Server:**
   Gunakan mekanisme session cookie berbasis token opaque yang dihasilkan secara kriptografis aman (misalnya UUID v4 dengan entropi 128-bit) dan petakan peran pengguna di sisi server melalui sesi basis data atau session cache terenkripsi.
3. **Penerapan Atribut Keamanan Cookie:**
   Jika enkapsulasi state pada cookie diperlukan (misalnya JWT), terapkan tanda tangan digital (HMAC-SHA256) serta pasang atribut proteksi: `HttpOnly` (mencegah pencurian XSS), `Secure` (hanya melalui HTTPS), dan `SameSite=Strict` (mitigasi CSRF).
4. **Taktik Uji LKS Cyber Security:**
   Ketika menghadapi skenario web dengan hint modifikasi cookie, prioritas pertama adalah memeriksa DevTools Application tab atau Storage tab, identifikasi pasangan key-value otorisasi, dan uji nilai batas logika boolean (`1`, `true`, `admin`, `root`).
