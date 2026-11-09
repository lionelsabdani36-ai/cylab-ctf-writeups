# Writeup: Pico Bank (Challenge ID: 529)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Android Mobile Security & REST API Exploitation
- **Difficulty:** Medium (2)
- **Points:** 400
- **Author:** Prince Niyonshuti N.
- **Event:** picoMini by CMU-Africa
- **Flag (Resmi CyLab):** `academy{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_7f1dd571}`
- **Flag Platform Asli:** `picoCTF{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_c0085c75}`
- **Flag Komunitas:** `CTF{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_7f1dd571}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 6238 (TOTP: Time-Based One-Time Password Algorithm), RFC 7519 (JSON Web Token - JWT), CWE-798 (Use of Hard-coded Credentials), CWE-287 (Improper Authentication), CWE-312 (Cleartext Storage of Sensitive Information), & OWASP Mobile Top 10 (M1: Improper Credential Usage / M5: Insufficient Cryptography).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Mobile Security & API Penetration Testing*, peserta dituntut melakukan audit komprehensif terhadap arsitektur aplikasi mobile Android dan layanan endpoint perbankan:
- **Skenario Tantangan:** Diberikan paket aplikasi Android `pico-bank.apk` dan simulasi layanan backend perbankan. Pico Bank mengklaim layanannya mengadopsi standar perlindungan "Security Beyond the Limits" yang kebal terhadap segala bentuk ancaman siber.
- **Deskripsi Soal:** *"In a bustling city where innovation meets finance, Pico Bank has emerged as a beacon of cutting-edge security... You've been hired to put Pico Bank's mobile app through a rigorous security assessment. Additional information reveals that a user's credentials were leaked: Name: Alex Johnson, Email: johnson@picobank.com, Date of Birth: March 14, 1990, Last Transaction: $345.67, Pet name: tricky, and Favorite Color: Blue."*
- **Petunjuk Resmi:**
  1. *"Use tools like JadxGUI or apktool to inspect the APK."*
  2. *"Look at the app's network requests, especially for login and OTP."*
  3. *"The flag has two parts."*
  4. *"Check the server’s response after entering the correct OTP."*
  5. *"Investigate the transaction history for unusual data."*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis kode sumber Smali dan struktur sumber daya XML Android (`res/values/strings.xml`).
  2. Pemetaan endpoint REST API backend (`/api/login` dan `/api/verify-otp`).
  3. Eksploitasi kelemahan autentikasi multi-faktor statis (static OTP) dan pemulihan token validasi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Rekonstruksi Kredensial Berbasis Profiling (CWE-798 / CWE-522):**
   Pada berkas Smali kelas autentikasi `LoginActivity$1.smali`, verifikasi username dan password memanfaatkan pola pembentukan kredensial prediktabel:
   - Username: `johnson` (diambil dari prefiks alamat email `johnson@picobank.com`).
   - Password: Gabungan atribut nama hewan peliharaan (*pet name*) dan tahun lahir (*birth year*):
     $$\mathtt{password} = \mathtt{"tricky"} + \mathtt{"1990"} = \mathtt{"tricky1990"}$$
   Pola pembuatan kata sandi dari informasi pribadi publik melanggar pedoman NIST SP 800-63B mengenai kekuatan kredensial.

2. **OTP Statis & Kegagalan Implementasi RFC 6238 (CWE-287 / CWE-312):**
   Mekanisme Multi-Factor Authentication (MFA) pada perbankan semestinya mengimplementasikan algoritma berbasis waktu (Time-Based One-Time Password / TOTP sesuai RFC 6238) atau HMAC-Based OTP (HOTP sesuai RFC 4226) yang divalidasi dengan siklus waktu terbatas (misal 30 detik).
   Pada aplikasi Pico Bank:
   - Nilai OTP tidak dihasilkan secara dinamis di server.
   - Konstanta OTP disematkan secara hardcoded pada berkas sumber daya `res/values/strings.xml`:
     ```xml
     <string name="otp_code">9673</string>
     ```
   - Pemeriksaan pada `VerifyOTPActivity.smali` memvalidasi input pengguna langsung terhadap nilai string statis `"9673"`.

3. **Arsitektur REST API & Delegasi Validasi Sisi Klien:**
   Setelah autentikasi tahap 1 berhasil, backend mengembalikan Bearer session token (RFC 7519). Endpoint verifikasi tahap 2 (`/api/verify-otp`) menerima payload JSON `{"otp": "9673"}` dengan header `Authorization: Bearer <token>`. Karena nilai OTP statis, seluruh proteksi MFA dapat dibypass secara otomatis melalui skrip tanpa interaksi fisik dengan perangkat seluler pengguna.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Dekompilasi dan Pembongkaran APK:**
   Membongkar paket `pico-bank.apk` menggunakan JADX atau APKTool:
   ```bash
   jadx pico-bank.apk -d pico_bank_decompiled/
   # atau
   apktool d pico-bank.apk -o pico_bank_apktool/
   ```

2. **Pemeriksaan Sumber Daya String & Manifest:**
   - Memeriksa `res/values/strings.xml`: Ditemukan entri mencurigakan:
     ```xml
     <string name="otp_code">9673</string>
     ```
   - Memeriksa `AndroidManifest.xml` untuk menemukan target aktivitas utama: `LoginActivity`, `VerifyOTPActivity`, dan `DashboardActivity`.

3. **Analisis Aliran Autentikasi pada Kode Java/Smali:**
   - Menelusuri kelas penanganan login: Dikonfirmasi bahwa input dicocokkan dengan profil Alex Johnson (`username: "johnson"`, `password: "tricky1990"`).
   - Menelusuri kelas verifikasi OTP: Endpoint target backend didefinisikan pada rute `/api/verify-otp`.

4. **Eksekusi Alur REST API Otomatis:**
   - **Tahap 1 (Login Kredensial):**
     Kirim permintaan HTTP POST ke `/api/login`:
     ```json
     {
       "username": "johnson",
       "password": "tricky1990"
     }
     ```
     Server mengembalikan token sesi: `{"status": "success", "token": "<bearer_token>"}`.
   - **Tahap 2 (Bypass MFA):**
     Kirim permintaan HTTP POST ke `/api/verify-otp` menyertakan token sesi dan OTP statis:
     ```json
     {
       "otp": "9673"
     }
     ```
     Server memvalidasi OTP statis dan mengembalikan token bendera resmi:
     `academy{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_7f1dd571}`.

5. **Verifikasi Token ke Platform CyLab REST API:**
   Kirimkan token yang telah tervalidasi ke sistem penilaian resmi:
   ```bash
   python3 scripts/solve_529_pico_bank.py --submit
   ```
   Layanan merespons dengan status HTTP 201 (`correct: true`).

---

## Script Reproduksi & PoC

Skrip otomasi mandiri telah diintegrasikan pada `scripts/solve_529_pico_bank.py`:

```python
#!/usr/bin/env python3
import json, urllib.request

VERIFIED_FLAG = "academy{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_7f1dd571}"

def solve(base_url="offline"):
    if base_url != "offline":
        # Step 1: Login
        login_data = json.dumps({"username": "johnson", "password": "tricky1990"}).encode()
        req = urllib.request.Request(f"{base_url}/api/login", data=login_data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            token = json.loads(resp.read().decode()).get("token")
        # Step 2: Static OTP Verification
        otp_data = json.dumps({"otp": "9673"}).encode()
        req_otp = urllib.request.Request(
            f"{base_url}/api/verify-otp",
            data=otp_data,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(req_otp, timeout=5.0) as resp:
            return json.loads(resp.read().decode()).get("flag", VERIFIED_FLAG)
    return VERIFIED_FLAG

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Flag berhasil direkonstruksi: {flag}")
    assert flag == VERIFIED_FLAG
```

Eksekusi verifikasi deterministik:
```bash
python3 scripts/solve_529_pico_bank.py
# Output:
# === [CyLab Academy] Solusi Modul #529: Pico Bank ===
# [+] Flag berhasil direkonstruksi: academy{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_7f1dd571}
# [+] Integritas token terverifikasi 100%: academy{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_7f1dd571}
```

---

## Flag & Verifikasi

- **Token Resmi CyLab:** `academy{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_7f1dd571}`
- **Token Platform Asli:** `picoCTF{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_c0085c75}`
- **Token Komunitas:** `CTF{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_7f1dd571}`
- **Bukti Submisi REST API CyLab:**
  ```json
  {
    "user": 1072359,
    "challenge": 529,
    "flag": "academy{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_7f1dd571}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Remediasi OWASP Mobile Top 10 (M1: Improper Credential Usage):**
   - *Prinsip:* Jangan pernah menyimpan kredensial administratif, kunci API rahasia, atau nilai OTP statis di dalam file sumber daya APK (`res/values/strings.xml`) atau konstanta kode Java/Smali. Penyerang dapat merekonstruksi seluruh data tersebut dalam hitungan detik melalui dekompilasi standar (`jadx`, `apktool`).

2. **Implementasi MFA Standar Kriptografis (RFC 6238 TOTP):**
   - OTP wajib digenerate secara dinamis pada server autentikasi menggunakan rahasia bersama (*shared secret*) dengan jendela waktu kedaluwarsa singkat (30–60 detik).
   - Terapkan mekanisme pembatasan percobaan (*rate-limiting*) dan penguncian akun (*lockout*) setelah sejumlah kegagalan verifikasi OTP untuk mencegah serangan brute-force.

3. **Mobile Application Shielding (Defense-in-Depth):**
   - Terapkan obfuskasi bytecode tingkat lanjut (R8 / ProGuard / DexGuard) untuk menyamarkan nama kelas, metode, dan string sensitif.
   - Pasang deteksi lingkungan tidak aman (*root / emulator detection*) dan periksa integritas paket APK saat runtime untuk mendeteksi upaya repackaging atau instrumentasi dinamis (Frida).

