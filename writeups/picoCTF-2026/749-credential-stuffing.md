# Writeup: Credential Stuffing (Challenge ID: 749)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Authentication Rate-Limiting & Credential Replay Analysis (NIST SP 800-115 §4.3)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{d0nt_r3u5e_cr3d3nt1als_9dee1556}`
- **Flag Komunitas:** `CTF{d0nt_r3u5e_cr3d3nt1als_9dee1556}`

---

## Problem Statement & Scope

Tantangan ini menyimulasikan skenario pengujian kerentanan autentikasi dan penanganan kebocoran kredensial pihak ketiga (*Credential Stuffing Attack*) pada antarmuka perbankan digital:
> *"A retail department store suffered a data breach, leaking a database dump of 1,500 username and password pairs. Threat intelligence indicates that one of the breached customers reused their exact corporate credentials on their Online Banking account. Can you identify the reused credentials, authenticate successfully, and retrieve the customer's account flag?"*

Laboratorium menyediakan berkas dump teks `creds-dump.txt` yang memuat 1.500 baris pasangan `username;password`. Layanan perbankan daring dijalankan pada port soket TCP (netcat) terisolasi. Saat klien terhubung, server mengirimkan banner penyambutan dan meminta input sekuensial:
```text
Welcome to the Online Banking Service!
Username: 
Password: 
```
Jika pasangan kredensial salah, server merespons dengan:
`Invalid username or password` dan menutup koneksi soket.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kegagalan Pembatasan Frekuensi Interaksi (CWE-799) & Percobaan Autentikasi Berlebih (CWE-307):**
   - Mekanisme autentikasi tidak membatasi laju permintaan (*Rate Limiting*) per alamat IP maupun per target akun (*Account Throttling*).
   - Server tidak menerapkan penundaan progresif (*Progressive Delay / Exponential Backoff*), CAPTCHA, maupun penguncian akun (*Account Lockout*) setelah serangkaian kegagalan login. Akibatnya, pengujian otomatis ribuan pasangan kredensial dapat diselesaikan hanya dalam hitungan detik hingga menit.

2. **Pengabaian Validasi Kredensial Terkompromi (NIST SP 800-63B §5.1.1.2):**
   - Standar NIST SP 800-63B mewajibkan verifier memeriksa kata sandi baru atau yang diubah terhadap daftar kata sandi yang telah terkompromi dalam insiden kebocoran publik (*Breach Corpus Check*).
   - Pengguna sering kali mendaur ulang (*password reuse*) kata sandi yang sama di berbagai platform (misalnya antara akun e-commerce retail dengan portal perbankan kritis). Tanpa verifikasi proaktif dan penegakan Multi-Factor Authentication (MFA), satu insiden kebocoran data pihak ketiga secara langsung meruntuhkan perimeter keamanan sistem lain.

3. **Oracle Respons Autentikasi Deterministik (Information Exposure via Output Discrepancy):**
   - Sistem mengembalikan respons yang jelas dan terprediksi: string `Invalid username or password` untuk login gagal versus `Welcome <user>!` beserta flag untuk login sukses. Ini memberikan *oracle* biner deterministik bagi skrip otomasi penyerang.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Reconnaissance & Analisis Korpus Kredensial:**
   - Mengunduh dan memeriksa berkas `creds-dump.txt`:
     ```bash
     wc -l creds-dump.txt
     # 1500 creds-dump.txt
     head -n 5 creds-dump.txt
     # rora;winner1
     # elena;sunshine2024
     # marcus;hunter2
     ```
   - Setiap baris memiliki format delimited titik koma: `<username>;<password>`.

2. **Probing Interaktif & Analisis Alur Protokol:**
   - Menghubungkan soket interaktif manual ke instance target:
     ```bash
     nc chatelaine.cylabacademy.net 46610
     # Welcome to the Online Banking Service!
     # Username: rora
     # Password: winner1
     # Invalid username or password
     ```
   - Alur autentikasi bersifat sinkron: menerima username, mengirimkan newline, menerima password, mengirimkan newline, membaca status respons.

3. **Otomasi Replay Serangan Credential Stuffing:**
   - Membangun skrip pengujian soket otomatis (`scripts/solve_749_credential_stuffing.py`).
   - Melakukan iterasi cepat terhadap pasangan kredensial. Pada pengujian entri #373:
     - Username: `ranna`
     - Password: `phoenix`
   - Server perbankan menerima pasangan kredensial dan mencetak token:
     ```text
     Welcome ranna!
     Here is your account flag: academy{d0nt_r3u5e_cr3d3nt1als_9dee1556}
     ```

4. **Verifikasi Token REST API:**
   - Token dievaluasi dan dikirimkan ke endpoint resmi CyLab `POST /api/submissions/`.
   - Respons platform mengonfirmasi validitas: HTTP 201 Created dengan status `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{d0nt_r3u5e_cr3d3nt1als_9dee1556}`
- **Format Komunitas:** `CTF{d0nt_r3u5e_cr3d3nt1als_9dee1556}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 749, "flag": "academy{d0nt_r3u5e_cr3d3nt1als_9dee1556}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Penerapan Multi-Factor Authentication (MFA / NIST SP 800-53 IA-2):**
   - Wajibkan otentikasi multi-faktor (FIDO2/WebAuthn atau TOTP) untuk seluruh akses akun finansial dan administratif. Meskipun kredensial primer bocor dalam dump eksternal, penyerang tidak dapat menyelesaikan autentikasi tanpa faktor kepemilikan fisik.

2. **Pembatasan Laju & Penguncian Progresif (CWE-307 / CWE-799 Remediation):**
   - Terapkan rate limiter pada reverse proxy/gateway (misalnya Nginx `limit_req_zone` atau Redis Token Bucket).
   - Terapkan *exponential backoff delay* setelah 3 percobaan gagal (misal: jeda 1 detik, 2 detik, 4 detik, hingga penguncian akun sementara 15 menit setelah 5 kegagalan).
   - Aktifkan tantangan CAPTCHA adaptif saat mendeteksi lonjakan kegagalan autentikasi dari rentang IP atau subnet tertentu.

3. **Pemeriksaan Korpus Kebocoran & Edukasi Keamanan (NIST SP 800-63B §5.1.1.2):**
   - Integrasikan API pemantau kebocoran kata sandi (seperti HaveIBeenPwned API dengan skema *k-anonymity*) saat pengguna melakukan pendaftaran atau penggantian kata sandi. Tolak kata sandi yang telah terkompromi dalam breach publik.
   - Edukasi pengguna untuk tidak mendaur ulang kata sandi lintas platform dan dorong penggunaan pengelola kata sandi (*Password Manager*).

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)

- **David (Leader):** Menetapkan parameter pengujian serangan credential stuffing dan menjamin kepatuhan metodologi NIST SP 800-115 §4.3.
- **Charlie (Trend-hunter):** Mengkaji tren soal LKS Bidang Cyber Security yang menitikberatkan pada aspek *Authentication Security, Threat Intelligence Analysis,* dan simulasi insiden kebocoran data.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Mengembangkan skrip otomasi pengujian soket jaringan dengan fitur simulator offline dan parser dump kredensial.
- **Julius (QA-engineer):** Menguji reliabilitas pengujian kredensial `ranna:phoenix` dan memverifikasi token terhadap API CyLab dengan status `correct: true`.
- **Athena (Security-engineer):** Merumuskan arsitektur mitigasi defensif berbasis NIST SP 800-63B dan pembatasan laju adaptif CWE-307/CWE-799.
- **Judith (Guru LKS):** Menyusun modul latihan kurikulum LKS terkait deteksi serangan kamus dan konfigurasi hardening kontrol autentikasi pada modul *Defensive Security*.
