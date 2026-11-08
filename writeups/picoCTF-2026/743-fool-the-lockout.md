# Writeup: Fool the Lockout (Challenge ID: 743)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / IP Rate-Limiter Evasion, Sliding-Window Flaw & Credential Stuffing (NIST SP 800-115 §4.3)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** David Gaviria
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{f00l_7h4t_l1m1t3r_2fa1cd8e}`
- **Flag Komunitas:** `CTF{f00l_7h4t_l1m1t3r_2fa1cd8e}`
- **Standar Referensi:** NIST SP 800-115 §4.3 (Application Security Assessment), OWASP WSTG-ATHN-03 (Testing for Account Lockout Mechanisms), NIST SP 800-63B §5.2.2 (Rate Limiting and Throttling Authentication Attempts), CWE-307 (Improper Restriction of Excessive Authentication Attempts), & CWE-799 (Improper Control of Interaction Frequency).

---

## Problem Statement & Scope
Pengembang membangun portal autentikasi berbasis Python Flask (`/login`) yang diamankan dengan mekanisme mitigasi serangan tebak kata sandi (*brute-force* dan *credential stuffing*) berbasis pelacak alamat IP:
- Parameter kontrol: `MAX_REQUESTS = 10`, `EPOCH_DURATION = 30` detik, `LOCKOUT_DURATION = 120` detik.
- Lampiran tantangan menyediakan dump kredensial pengguna publik (`creds-dump.txt`, 100 baris pasangan `username;password`) dan kode sumber aplikasi `app.py`.
- Sasaran pengujian: Menganalisis kelemahan perancangan logika *rate limiting* pada batas jendela waktu (*epoch boundary*), melakukan *credential stuffing* terukur tanpa terpicu pemblokiran IP permanen, menemukan kredensial akun sah, dan mengekstraksi flag dari dashboard utama (`GET /`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Logika Reset Jendela Diskrit Cacat (CWE-799)
Implementasi pelacak frekuensi permintaan pada fungsi `refresh_request_rates_db(client_ip)` menggunakan model jendela waktu berbasis selisih epoch sederhana:
```python
def refresh_request_rates_db(client_ip):
    curr_time = time.time()
    if client_ip in request_rates:
        if curr_time - request_rates[client_ip]['epoch_start'] > EPOCH_DURATION:
            request_rates[client_ip]['num_requests'] = 0
            request_rates[client_ip]['epoch_start'] = curr_time
```
Kelemahan fatal pada logika ini adalah penghitung `num_requests` langsung di-reset secara seketika (*abrupt zeroing*) ke angka 0 begitu selisih waktu melebihi 30 detik sejak permintaan pertama dalam epoch tersebut. Ini bukan model *sliding window* atau *leaky bucket* yang mengalirkan token secara kontinu, melainkan *fixed window* diskrit.

### 2. Ketiadaan Pelacakan Berbasis Akun Pengguna / Missing Account Lockout (CWE-307)
Mekanisme pembatasan hanya mengaitkan kuota permintaan pada alamat IP pemanggil (`client_ip`). Aplikasi tidak menerapkan pencatatan kegagalan login pada entitas akun pengguna (*per-account failure tracking*). Konsekuensinya:
- Penyerang yang mengendalikan tempo permintaan (*request pacing*) dapat mengirimkan hingga 10 tebakan sekaligus per epoch.
- Dengan menyisipkan jeda waktu $T > 30$ detik di antara setiap batch 10 percobaan, penghitung `num_requests` kembali menjadi nol tanpa pernah melewati ambang batas $11$ yang memicu durasi penguncian (`LOCKOUT_DURATION = 120s`).

### 3. Model Serangan Credential Stuffing Terdistribusi & Bertahap
Dalam kerangka NIST SP 800-63B, kontrol pertahanan autentikasi wajib membatasi akumulasi upaya login gagal terhadap akun spesifik dari banyak IP (serangan *spray/stuffing* terdistribusi) serta membatasi total volume dari satu IP tunggal. Karena aplikasi hanya menerapkan satu sisi kontrol yang lemah pada IP, seluruh 100 pasangan kredensial dapat diuji dalam 10 siklus waktu (~300 detik), atau di-bypass seketika begitu kredensial pengguna sasaran berhasil diidentifikasi.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Audit Logika Pengontrol Frekuensi `app.py`
Analisis terhadap alur kontrol menunjukkan kondisi pemicu blokir:
```python
def exceeded_rate_limit(client_ip):
    refresh_request_rates_db(client_ip)
    if client_ip in request_rates:
        if request_rates[client_ip]['num_requests'] > MAX_REQUESTS:
            request_rates[client_ip]['lockout_until'] = time.time() + LOCKOUT_DURATION
            return True
        if time.time() < request_rates[client_ip]['lockout_until']:
            return True
    return False
```
Penyerang dapat mengirim tepat 10 percobaan tanpa memicu penguncian (`num_requests <= 10`).

### Langkah 2: Audit Daftar Kredensial `creds-dump.txt`
Daftar kredensial memuat 100 baris akun. Pengujian batch bertahap (10 percobaan per jendela 31 detik) menemukan bahwa pasangan akun yang valid berada pada baris:
$$\text{Username: } \texttt{cecile} \quad | \quad \text{Password: } \texttt{makaveli}$$

### Langkah 3: Autentikasi Langsung & Ekstraksi Sesi
Dengan mengetahui kredensial yang tepat:
1. Mengirim permintaan HTTP `POST /login` dengan payload terenkode:
   `username=cecile&password=makaveli`
2. Server Flask memvalidasi kredensial pengguna, menyimpan `session['user'] = 'cecile'`, dan mengembalikan respons pengalihan (HTTP 302 / 200).
3. Melakukan permintaan HTTP `GET /` dengan cookie sesi aktif. Server merender konten flag dari `/challenge/flag.txt`:
   `academy{f00l_7h4t_l1m1t3r_2fa1cd8e}`.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{f00l_7h4t_l1m1t3r_2fa1cd8e}`
- **Flag Format Komunitas:** `CTF{f00l_7h4t_l1m1t3r_2fa1cd8e}`
- **Verifikasi Live REST API CyLab:**
  Submisi ke `https://learn.cylabacademy.org/api/submissions/` mengembalikan respons status HTTP 201:
  `{"user": 1072359, "challenge": 743, "flag": "academy{f00l_7h4t_l1m1t3r_2fa1cd8e}", "correct": true, "historical": false}`.
- **Verifikasi Simulasi Offline:** Skrip `scripts/solve_743_fool_the_lockout.py` memvalidasi komponen `LockoutSimulator` untuk memverifikasi model batas epoch dan ekstraksi bendera secara mandiri tanpa container eksternal.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Implementasi Algoritma Leaky Bucket / Token Bucket
Hindari reset diskrit berbasis jendela waktu statis. Terapkan algoritma **Token Bucket** atau **Generic Cell Rate Algorithm (GCRA)** menggunakan penyimpanan terdistribusi seperti Redis:
- Setiap permintaan mengonsumsi token dari wadah.
- Token diisi ulang secara kontinu per unit milidetik.
- Lonjakan (*burst*) di perbatasan waktu tidak dapat dieksploitasi untuk melipatgandakan kuota serangan.

### 2. Throttling Bertingkat Berdasarkan Identitas Akun (NIST SP 800-63B)
Kombinasikan kontrol pembatasan laju (*rate limiting*) pada tiga dimensi:
1. **Per-IP Rate Limiting:** Melindungi infrastruktur dari *Denial of Service* (DoS).
2. **Per-Account Rate Limiting:** Kunci akun atau minta verifikasi tambahan setelah 5 kegagalan berturut-turut pada pengguna yang sama, terlepas dari variasi IP penyerang.
3. **Global Failure Rate Throttling:** Deteksi lonjakan kegagalan autentikasi global di seluruh aplikasi.

### 3. Penerapan Multi-Factor Authentication (MFA) & CAPTCHA Adaptif
Terapkan tantangan CAPTCHA interaktif (misalnya Cloudflare Turnstile atau reCAPTCHA v3) setelah 3 kali upaya login gagal pada sesi tertentu, dan wajibkan MFA berbasis TOTP atau FIDO2/WebAuthn untuk mengeliminasi risiko pembajakan akun akibat kebocoran kredensial publik.
