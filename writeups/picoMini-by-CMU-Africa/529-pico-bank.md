# Writeup: Pico Bank (Challenge ID: 529)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Android Mobile & API
- **Difficulty:** Medium
- **Event:** picoMini by CMU-Africa
- **Points:** 400
- **Author:** Prince Niyonshuti N.
- **Flag:** `academy{st4t1c_0tp_4nd_sm4l1_r3v_529}` (Native: `picoCTF{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_c0085c75}`)

---

## Problem Statement & Scope
Diberikan artefak aplikasi perbankan seluler Android (`pico-bank.apk`) dan layanan endpoint backend simulasi verifikasi transaksi. Pengguna diinstruksikan melakukan audit keamanan terhadap mekanisme autentikasi dan transfer dana untuk mengekstrak token rahasia perbankan.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Hardcoded Credentials & Cleartext Storage (CWE-798, CWE-312):**
   Aplikasi menyimpan kredensial administratif dasar secara statis di dalam string tabel dan konstanta Smali (`username = "johnson"`, `password = "tricky1990"`), melanggar prinsip pemisahan rahasia pada arsitektur mobile.
2. **Static One-Time Password / Broken Authentication (CWE-287 / RFC 6238):**
   Mekanisme Multi-Factor Authentication (MFA/OTP) tidak di-generate secara dinamis menggunakan algoritma kriptografis berbasis waktu (TOTP) di server, melainkan di-hardcode sebagai nilai statis `9673` pada berkas `res/values/strings.xml`.
3. **Client-Side Security Logic Devolution:**
   Integritas transaksi dan validasi sesi sepenuhnya dipercayakan pada kontrol logika sisi klien Android tanpa verifikasi kriptografis end-to-end di backend.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Dekompilasi APK:**
   Bongkar paket APK menggunakan `jadx` atau `apktool`:
   ```bash
   jadx pico-bank.apk -d pico_bank_src/
   ```
2. **Inspeksi String & Sumber Daya XML:**
   Cari pola OTP atau kata sandi di `res/values/strings.xml`:
   ```xml
   <string name="otp_code">9673</string>
   ```
3. **Analisis Logika Smali / Java:**
   Periksa kelas `LoginActivity` dan `VerifyOTPActivity`. Temukan pasangan kredensial hardcoded:
   - Username: `johnson`
   - Password: `tricky1990`
4. **Eksekusi Eksploitasi REST API:**
   - Kirim permintaan autentikasi awal:
     `POST /api/login` dengan muatan `{"username": "johnson", "password": "tricky1990"}` untuk memperoleh Bearer token.
   - Kirim verifikasi MFA menggunakan OTP statis:
     `POST /api/verify-otp` dengan header `Authorization: Bearer <token>` dan muatan `{"otp": "9673"}`.
5. **Pemulihan Token:**
   Layanan merespons dengan payload JSON yang memuat token penyelesaian resmi: `academy{st4t1c_0tp_4nd_sm4l1_r3v_529}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{st4t1c_0tp_4nd_sm4l1_r3v_529}`
- **Flag Platform Asli:** `picoCTF{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_c0085c75}`
- **Status Solver:** Terverifikasi melalui skrip reproduktif `scripts/solve_529_pico_bank.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **OWASP Mobile Top 10 (M1: Improper Credential Usage / M5: Insufficient Cryptography):**
  Jangan pernah menyematkan kredensial statis atau token autentikasi di dalam kode klien atau sumber daya APK.
- **Implementasi MFA Standar:**
  Wajibkan implementasi RFC 6238 (TOTP) yang divalidasi dengan time-window ketat di sisi server perbankan.
- **Mobile Hardening:**
  Terapkan obfuskasi bytecode R8/ProGuard, certificate pinning TLS, dan deteksi tampering/rooting (RASP) untuk modul kompetensi Mobile Security LKS.
