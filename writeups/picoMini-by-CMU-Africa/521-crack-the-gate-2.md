# Writeup: Crack the Gate 2 (Challenge ID: 521)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Authentication Rate-Limit Bypass via Header Spoofing
- **Difficulty:** Medium (2)
- **Author:** CMU-Africa Team
- **Event:** picoMini by CMU-Africa
- **Points:** 100
- **Flag:** `academy{xff_byp4ss_brut3_b6771b85}`

---

## Problem Statement & Scope
> The login system has been upgraded with a basic rate-limiting mechanism that locks out repeated failed attempts from the same source. We’ve received a tip that the system might still trust user-controlled headers. Your objective is to bypass the rate-limiting restriction and log in using the known email address: **ctf-player@cylabacademy.org** and uncover the hidden secret.
> The website is running `http://chatelaine.cylabacademy.net:<port>/`.
> Download the passwords list `passwords.txt`.
> Hints:
> 1. What IP does the server think you’re coming from?
> 2. Read more about X-Forwarded-For.
> 3. You can rotate fake IPs to bypass rate limits.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kepercayaan Header Klien Tanpa Validasi (Insecure Header Trust / CWE-348):**
   - Saat aplikasi web berjalan di belakang reverse proxy, aplikasi kerap mengambil identitas alamat IP klien melalui header HTTP seperti `X-Forwarded-For` atau `X-Real-IP`.
   - Jika konfigurasi reverse proxy atau middleware aplikasi tidak memvalidasi atau memfilter header yang dikirim oleh klien secara langsung, penyerang dapat menyuntikkan (spoof) alamat IP palsu dalam setiap permintaan.
2. **Kelemahan Implementasi Rate Limiting Berbasis IP:**
   - Mekanisme proteksi brute-force yang hanya mengandalkan nilai `X-Forwarded-For` mentah dari klien dapat sepenuhnya dihindari dengan melakukan rotasi IP palsu pada setiap percobaan autentikasi (misal: `192.168.1.10`, `192.168.1.11`, dst).
   - Setiap percobaan dianggap berasal dari host yang berbeda oleh rate limiter, sehingga ambang batas penguncian (lockout threshold) tidak pernah tercapai untuk IP mana pun.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis Endpoint Autentikasi:
   - Form web mengirimkan permintaan JSON `POST /login` dengan payload:
     `{"email":"ctf-player@cylabacademy.org","password":"<password>"}`.
2. Daftar Kata Sandi:
   - Terdapat 20 kandidat kata sandi dari `passwords.txt`.
3. Otomasi Pengujian dengan Rotasi Header `X-Forwarded-For`:
   - Kirimkan permintaan autentikasi sekuensial dengan menambahkan header `X-Forwarded-For: 192.168.1.<10+index>`.
   - Percobaan ke-7 dengan kata sandi `GuNjjI8t` dan IP `192.168.1.16` berhasil menghasilkan respons sukses:
   ```json
   {
     "success": true,
     "email": "ctf-player@cylabacademy.org",
     "firstName": "pico",
     "lastName": "player",
     "flag": "academy{xff_byp4ss_brut3_b6771b85}"
   }
   ```
4. Eksekusi Script Solver:
   ```bash
   python3 scripts/solve_521_crack_the_gate_2.py http://chatelaine.cylabacademy.net:27886/
   ```
5. Verifikasi REST API CyLab:
   - Endpoint `POST /api/submissions/` merespons dengan status HTTP 201 Created:
   ```json
   {"user": 1072359, "challenge": 521, "flag": "academy{xff_byp4ss_brut3_b6771b85}", "correct": true, "historical": false}
   ```

---

## Pembelajaran Defensif & Mitigasi LKS
- **Konfigurasi Reverse Proxy Tepercaya (`trust proxy`):** Di Express.js, pastikan pengaturan `app.set('trust proxy', 'loopback')` atau subnet proxy tepercaya secara eksplisit agar aplikasi tidak mempercayai header spoofing dari klien internet publik.
- **Sanitasi Header `X-Forwarded-For` di Edge/Ingress:** Reverse proxy terdepan (seperti Nginx atau Cloudflare) wajib menimpa (`proxy_set_header X-Forwarded-For $remote_addr;`) atau menghapus header `X-Forwarded-For` yang dikirim dari klien sebelum meneruskannya ke backend.
- **Rate Limiting Multidimensi:** Terapkan pembatasan percobaan tidak hanya berdasarkan alamat IP, melainkan kombinasi multidimensi: kombinasi akun target (`email`), fingerprint sesi, dan CAPTCHA adaptif setelah kegagalan berulang.
- **Account Lockout & Monitoring:** Terapkan penundaan respons progresif (*exponential backoff*) untuk akun pengguna yang mengalami kegagalan login berturut-turut.
