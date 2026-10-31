# 697 - The Add/On Trap (Reverse Engineering, picoCTF 2026, Medium)

## Challenge Metadata
- ID: 697 | Event: picoCTF 2026 | Author: Yahya Meddy
- Category: Reverse Engineering | Difficulty: Medium (2)
- Flag: `academy{Us3_4dd/0ns_v3ry_c4r3fully1}`

## Problem Statement & Scope
Tantangan mendistribusikan arsip `suspicious.zip` (password: `academy`) yang memuat ekstensi peramban Firefox berekstensi `.xpi` (`56102ec0438646c68605-1.0.xpi`). Ekstensi menyamar sebagai layanan geolokasi alamat IP ("Geolocate IP Addresses"), namun di balik layar menjalankan eksfiltrasi URL riwayat browsing pengguna. Peserta diminta menginspeksi kode sumber ekstensi untuk mengungkap flag yang tersembunyi.

## Teori & Akar Kerentanan (Root Cause)
1. **Anatomi Paket Ekstensi Web (`.xpi` Archive):**
   File berekstensi `.xpi` (Cross-Platform Installer) merupakan arsip berformat standar ZIP (RFC 1951). Komponen internal mencakup `manifest.json`, script latar belakang (`background/main.js`), interface popup (`popup.html`, `assets/script.js`), serta metadata penandatanganan kriptografis (`META-INF/`).
2. **Hardcoded Cryptographic Material (CWE-321 / CWE-798):**
   Pada script latar belakang `background/main.js`, pengembang menyematkan kunci enkripsi secara statis:
   ```javascript
   const key = "YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0=";
   ```
   Kunci ini merupakan string URL-safe Base64 sepanjang 32 byte:
   `base64_decode(key) = "academy{you're on the right tra}"`.
3. **Fernet Symmetric Cryptographic Scheme (RFC 0001 / Fernet Spec):**
   Spesifikasi Fernet menerapkan enkripsi simetris terotentikasi (AES-128 dalam mode CBC dengan HMAC-SHA256 untuk integritas dan timestamp 64-bit). Ciphertext Fernet selalu diawali dengan token `gAAAAA`. Variabel `webhookUrl` yang menampung alamat endpoint eksfiltrasi terenkripsi dengan Fernet menggunakan kunci statis di atas.

## Rekonstruksi Eksploitasi Step-by-Step
1. Ekstraksi arsip tantangan:
   - `unzip -P academy suspicious.zip` -> diperoleh file `56102ec0438646c68605-1.0.xpi`.
   - `unzip 56102ec0438646c68605-1.0.xpi -d xpi_contents`.
2. Analisis file konfigurasi dan skrip:
   - `manifest.json`: meminta hak akses `permissions: ["webNavigation"]` dan mendaftarkan `background/main.js`.
   - `background/main.js`: menambahkan listener pada `browser.webNavigation.onCompleted`. Setiap kali pengguna mengunjungi URL, ekstensi mencoba mengeksfiltrasi URL tersebut via POST request ke `webhookUrl`.
3. Identifikasi ciphertext dan kunci:
   - Kunci URL-safe Base64: `YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0=`.
   - Ciphertext `webhookUrl` diawali dengan signature Fernet `gAAAAABqU...`.
4. Dekripsi muatan token dengan pustaka `cryptography.fernet`:
   ```python
   from cryptography.fernet import Fernet
   key = b"YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="
   cipher = Fernet(key)
   flag = cipher.decrypt(token_bytes).decode("utf-8")
   # Hasil: 'academy{Us3_4dd/0ns_v3ry_c4r3fully1}'
   ```
5. Verifikasi flag via API CyLab:
   `POST /api/submissions/` dengan payload `{"challenge": 697, "flag": "academy{Us3_4dd/0ns_v3ry_c4r3fully1}"}` -> respons `{"correct": true}`.

## Flag & Verifikasi
- `academy{Us3_4dd/0ns_v3ry_c4r3fully1}` (Status: Verified `correct: true`, `historical: false`).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Third-Party Extension Vetting & Supply Chain Security:** Browser extensions memiliki akses luas terhadap data sesi dan navigasi peramban. Dalam lingkungan korporat/pemerintahan, kebijakan grup (GPO / Enterprise Policies) harus membatasi instalasi ekstensi yang tidak masuk dalam whitelist terverifikasi.
- **Principle of Least Privilege:** Hindari pemberian izin `webNavigation` atau `webRequest` pada ekstensi jika fitur fungsionalitas utama (misalnya geolokasi IP) hanya memerlukan operasi pasif pada popup frontend.
