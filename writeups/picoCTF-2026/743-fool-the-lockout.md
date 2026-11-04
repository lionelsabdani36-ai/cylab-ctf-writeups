# 743 - Fool the Lockout (Web Exploitation, picoCTF 2026, Medium)

## Challenge Metadata
- ID: 743 | Event: picoCTF 2026
- Category: Web Exploitation | Difficulty: Medium (2)
- Author: David Gaviria
- Flag: `academy{f00l_7h4t_l1m1t3r_2fa1cd8e}`

## Problem Statement & Scope
Pengembang membangun portal autentikasi berbasis Flask (`/login`) yang dilengkapi mekanisme mitigasi brute-force berupa IP-based rate limiter:
- Parameter: `MAX_REQUESTS = 10`, `EPOCH_DURATION = 30` detik, `LOCKOUT_DURATION = 120` detik.
- Tersedia dump kredensial publik (`creds-dump.txt`, 100 baris pasangan `username;password`) dan kode sumber lengkap `app.py`.
- Objektif audit (NIST SP 800-115 / OWASP WSTG-ATHN-03): menganalisis batasan arsitektur rate limiter, mengelak dari pemblokiran (fool the lockout), menemukan akun valid, dan mengekstrak flag dari dashboard index.

## Teori & Akar Kerentanan (Root Cause)
1. **Flawed Sliding-Window Reset Logic:**
   Fungsi `refresh_request_rates_db(client_ip)` memeriksa selisih waktu `curr_time - epoch_start > EPOCH_DURATION`. Jika lebih dari 30 detik berlalu sejak request pertama dalam epoch, `num_requests` di-reset ke 0.
2. **Missing State Check on Lockout Period:**
   Pada fungsi `exceeded_rate_limit()`, blok pemblokiran hanya memeriksa `request_rates[client_ip]['num_requests'] > MAX_REQUESTS`. Logika ini tidak mengecek status flag `lockout_until != -1` secara independen jika `num_requests` telah ter-reset.
3. **Evasion via Controlled Request Pacing:**
   Penyerang dapat mengirimkan tepat 10 request dalam waktu singkat, kemudian menunggu jeda waktu $T > 30$ detik (epoch boundary reset) sebelum mengirimkan 10 request berikutnya. Dengan pacing ini, penghitung request tidak pernah menumpuk melewati ambang batas pemblokiran aktif, memungkinkan stuffing 100 pasangan kredensial secara deterministik tanpa terkunci permanen.

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis arsitektur `app.py`:
   - Endpoint `/login` memproses POST `username` dan `password`.
   - Kegagalan login memicu pesan `Invalid username or password`.
   - Keberhasilan login mengeset cookie sesi Flask `session['user']` dan mengarahkan ke route `/` yang merender flag dari `/challenge/flag.txt`.
2. Provisioning lab instance container:
   - Target HTTP endpoint live di `http://chatelaine.cylabacademy.net:16947/`.
3. Automasi Credential Stuffing dengan Evasion:
   - Membaca 100 baris dari `creds-dump.txt`.
   - Mengirim request POST secara batch: 10 attempt per batch dengan `time.sleep(31)` antar batch untuk mereset epoch rate limiter.
4. Pada batch ke-10 (indeks 91):
   - Kredensial valid ditemukan: `cecile:makaveli`.
   - Server mengembalikan redirect ke `/` dengan sesi aktif.
5. Permintaan GET ke `/` mengekstrak flag resmi:
   `academy{f00l_7h4t_l1m1t3r_2fa1cd8e}`.
6. Verifikasi dan pembersihan:
   - Mengirim token flag ke REST API `POST /api/submissions/` -> HTTP 201 `correct: true`.
   - Terminasi instance lab via `DELETE /api/challenges/743/instance/`.

## Flag & Verifikasi
- Flag: `academy{f00l_7h4t_l1m1t3r_2fa1cd8e}` (HTTP 201 `correct: true`, user 1072359).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Per-Account & Global Throttling:** Rate limiter tidak boleh hanya bergantung pada IP address (yang dapat dipalsukan melalui reverse-proxy misconfiguration atau dievasi dengan distributed botnet/delay). Terapkan progressive lockout per target username.
- **Leaky Bucket / Token Bucket Algorithm:** Gantikan window diskrit berbasis epoch reset sederhana dengan algoritma Leaky Bucket atau Token Bucket (misal via Redis ratelimit) untuk mencegah burst evasion di batas epoch.
- **Multi-Factor Authentication (MFA) & CAPTCHA:** Terapkan CAPTCHA interaktif setelah 3 percobaan gagal dan wajibkan MFA untuk menghentikan serangan credential stuffing secara menyeluruh sesuai standar NIST SP 800-63B.
