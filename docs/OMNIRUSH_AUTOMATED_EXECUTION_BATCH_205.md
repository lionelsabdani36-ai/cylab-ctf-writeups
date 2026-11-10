# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 205

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (279, 280, 282). Kelanjutan Event picoCTF 2022 (29/65 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 205 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 205, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian sekuensial 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan event picoCTF 2022 (#279 Lookey here, #280 morse-code, #282 noted), memverifikasi artefak korpus teks novel Anthem 108 KB, rekaman sinyal audio PCM WAV 44.1 kHz, serta aplikasi web Node.js/Express note-taking |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan keterbukaan token dalam korpus besar tanpa enkripsi (CWE-312 / CWE-200), modulasi sinyal akustik CW tanpa perlindungan kriptografi (ITU-R M.1677-1 / CWE-319), serta Login CSRF dan kebocoran DOM lintas jendela Same-Origin Policy (CWE-352 / CWE-79) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekayasa dan memperbarui skrip solver otomatis mandiri `solve_279_lookey_here.py`, `solve_280_morse_code.py`, dan `solve_282_noted.py`, serta membangun suite uji deterministik `test_batch_205_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 574/574 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform (HTTP 201 correct:true), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: teknik text carving dan inspeksi regex berkecepatan tinggi, metodologi otomasi demodulasi sinyal audio via Python stdlib, serta mitigasi pertahanan Login CSRF dan arsitektur SOP modern |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada lingkungan VPS (`lionelsabdani36@gmail.com`).
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_205_harness.py`.
- **Eksekusi Pengganti:** Orkestrasi coding agent dijalankan melalui toolchain internal Hermes dan harness deterministik Python karena layanan upstream sandbox OmniRush saat ini dalam status pemeliharaan berkala.

---

## 3. Sinkronisasi Sesi REST API CyLab

| Parameter | Nilai / Status |
| :--- | :--- |
| Endpoint Pemeriksaan Sesi | `GET /api/challenges/?page_size=1` -> **HTTP 200 OK** (katalog 525 item) |
| Kredensial & Autentikasi | `cf_clearance` + `sessionid` + `csrftoken` aktif dari `/tmp/cylab_auth.py` |
| Akun Siswa Terautentikasi | `Arielwin` (user id `1072359`) |
| Endpoint Penyerahan Bendera | `POST /api/submissions/` dengan header `X-CSRFToken` |

---

## 4. Analisis Arsitektur, RFC, dan Rekonstruksi per Modul

### Modul 1: ID 279 `Lookey here` (Forensics, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Korpus teks sastra Ayn Rand *Anthem* berukuran 107,994 byte (2,146 baris) dalam format UTF-8 polos (`anthem.flag.txt`).
- **Akar Kerentanan (CWE-312 / CWE-200 / NIST SP 800-115 § 5.3):**
  1. Token rahasia disisipkan secara langsung di antara baris teks novel tanpa enkripsi simetris maupun transformasi hashing.
  2. Format pembungkus bendera mempertahankan pola awalan baku `academy{...}`, memungkinkan ekstraksi linier $O(N)$ melalui ekspresi reguler tanpa perlu inspeksi visual manual.
- **Validasi Validator:** Submisi token `academy{gr3p_15_@w3s0m3_33595e98}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 280 `morse-code` (Cryptography, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Berkas rekaman audio Microsoft PCM 16-bit mono 44.1 kHz berdurasi ~28.9 detik (`morse_chal.wav`) yang memodulasi gelombang sinusoidal ~800 Hz.
- **Akar Kerentanan (ITU-R M.1677-1 / CWE-319 / NIST SP 800-115 § 5.3):**
  1. Pengiriman pesan rahasia dilakukan via kanal audio terbuka tanpa perlindungan kriptografi (*cleartext audible acoustic modulation*).
  2. Rasio durasi pulsa nada aktif mengikuti spesifikasi baku ITU-R M.1677-1 (dot = 100 ms, dash = 300 ms, inter-element = 100 ms, inter-character = 400 ms, inter-word = 800 ms).
  3. Demodulasi deterministik berbasis detektor energi RMS jendela 10 ms dan encoding run-length merekonstruksi seluruh simbol leetspeak (`WH47`, `H47H`, `90D`, `W20U9H7`) secara otomatis.
- **Validasi Validator:** Submisi token `academy{WH47_H47H_90D_W20U9H7}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 282 `noted` (Web Exploitation, Hard, picoCTF 2022)
- **Arsitektur & Batas Input:** Aplikasi web pencatatan multi-pengguna Node.js Express dengan bot verifikasi headless Chromium (Puppeteer) yang mengelola catatan privat `process.env.FLAG`.
- **Akar Kerentanan (CWE-352 / CWE-79 / NIST SP 800-115 § 4.3):**
  1. Template penampil catatan merender HTML masukan pengguna tanpa sanitasi entitas (Self-XSS terisolasi).
  2. Rute autentikasi `POST /login` tidak memiliki validasi token anti-CSRF atau mitigasi cookie SameSite ketat (Login CSRF).
  3. Kepatuhan peramban terhadap Same-Origin Policy (SOP) mengizinkan dokumen dengan skema, domain, dan port identik (`http://localhost:8080`) mengakses hierarki DOM jendela anak (`window.name`).
  4. Penyerang membuka catatan rahasia admin pada jendela anak, memicu Login CSRF ke akun penyerang pada jendela induk, lalu mengeksekusi payload Self-XSS yang membaca teks `document.body.innerText` dari jendela anak.
- **Validasi Validator:** Submisi token `academy{p00rth0s_parl1ment_0f_p3p3gas_386f0184}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_205_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (574/574 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_279`: **PASS** (reproduksi text carving regex exit 0, token cocok).
3. `solve_280`: **PASS** (reproduksi demodulasi audio PCM Morse exit 0, token cocok).
4. `solve_282`: **PASS** (reproduksi Login CSRF dan cross-window DOM leak exit 0, token cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/picoCTF-2022/`, zero em dash).
