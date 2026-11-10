# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 194

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 §4.2 (analisis kerentanan), §4.3 (validasi terkontrol), §4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (245, 246, 247). Kelanjutan Audit Event Beginner picoMini 2022 (9/13 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 194 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint kelanjutan event Beginner picoMini 2022 (#245, #246, #247), kepatuhan NIST SP 800-115, dan integrasi repositori |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul seri PW Crack (#245, #246, #247) pada event `Beginner picoMini 2022` yang memerlukan audit standar LKS dan verifikasi wrapper platform |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis penggunaan kredensial hardcoded (CWE-259 / CWE-798), kegagalan konsep obfuskasi karakter ordinal ASCII heksadesimal (Security through Obscurity), dan analisis kelemahan algoritma hashing MD5 untuk kredensial serta serangan kamus terarah (CWE-327 / NIST SP 800-115 §5) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Memverifikasi dan mengoptimasi skrip solver `solve_245`, `solve_246`, `solve_247` dengan mode reproduksi offline deterministik serta membangun suite uji test harness `test_batch_194_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi live `POST /api/submissions/` dengan CSRF token, sweep AST 563/563 skrip Python tanpa regresi, pengujian wrapper matrix (academy vs picoCTF), dan validasi JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun materi kurikulum bimbingan teknis LKS Cyber Security: analisis kode statis (SAST), deobfuskasi representasi karakter, dan pengujian integritas hash password sesuai standar keamanan industri |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang dan siap digunakan pada VPS.
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_194_harness.py`.
- **Eksekusi Pengganti:** Orkestrasi coding agent dijalankan melalui toolchain internal Hermes dan harness deterministik Python.

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

### Modul 1: ID 245 `PW Crack 1` (General Skills, Easy, Beginner picoMini 2022)
- **Arsitektur & Batas Input:** Skrip Python `level1.py` bersama berkas cipher biner `level1.flag.txt.enc` yang meminta masukan string kata sandi melalui prompt konsol.
- **Akar Kerentanan (CWE-259 / CWE-798):**
  1. Kode sumber melakukan perbandingan langsung teks terang terhadap nilai hardcoded:
     `if (user_pw == "1e1a"):`
  2. Kredensial terbuka secara langsung dalam inspeksi statis kode sumber tanpa memerlukan teknik komputasi kompleks.
  3. Kunci `"1e1a"` digunakan langsung dalam algoritma dekripsi stream XOR modular terhadap berkas `level1.flag.txt.enc`.
- **Validasi Validator:** Submisi token `academy{545h_r1ng1ng_4a96bf39}` menghasilkan **HTTP 201 Created (`correct: true`)**. Varian `picoCTF{...}` ditolak validator (`correct: false`).

### Modul 2: ID 246 `PW Crack 2` (General Skills, Easy, Beginner picoMini 2022)
- **Arsitektur & Batas Input:** Skrip Python `level2.py` dan berkas cipher `level2.flag.txt.enc` dengan mekanisme verifikasi kata sandi terobfuskasi.
- **Akar Kerentanan (CWE-259 / CWE-798 / Obfuscation):**
  1. Kode program mencoba menyembunyikan string kata sandi menggunakan konkatenasi pemanggilan fungsi ordinal karakter ASCII `chr(0x64) + chr(0x65) + chr(0x37) + chr(0x36)`.
  2. Evaluasi statis titik kode integer heksadesimal memetakan nilai menjadi `'d' + 'e' + '7' + '6'` -> `"de76"`.
  3. Obfuskasi bita/karakter tidak menyediakan perlindungan kriptografis (Security through Obscurity) dan dapat dievaluasi seketika.
  4. Dekripsi stream XOR menggunakan kunci `"de76"` memulihkan teks terang bendera.
- **Validasi Validator:** Submisi token `academy{tr45h_51ng1ng_ab548076}` menghasilkan **HTTP 201 Created (`correct: true`)**. Varian `picoCTF{...}` ditolak validator (`correct: false`).

### Modul 3: ID 247 `PW Crack 3` (General Skills, Medium, Beginner picoMini 2022)
- **Arsitektur & Batas Input:** Skrip Python `level3.py`, berkas hash intisari biner `level3.hash.bin` (16 bita), dan berkas cipher `level3.flag.txt.enc`.
- **Akar Kerentanan (CWE-327 / RFC 1321 / NIST SP 800-115 §5):**
  1. Skrip menggunakan algoritma hash MD5 tanpa salt untuk memverifikasi kecocokan kata sandi.
  2. Skrip menyediakan daftar 7 kandidat potensial pada variabel `pos_pw_list` (`["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"]`), mereduksi ruang entropi pencarian menjadi $\mathcal{O}(7)$.
  3. Serangan kamus terarah mengevaluasi intisari MD5 untuk ketujuh kandidat dan mengidentifikasi kecocokan sempurna pada kandidat `"ec27"` terhadap isi `level3.hash.bin`.
  4. Dekripsi stream XOR pada `level3.flag.txt.enc` dengan kunci `"ec27"` menghasilkan token bendera resmi.
- **Validasi Validator:** Submisi token `academy{m45h_fl1ng1ng_b8034615}` menghasilkan **HTTP 201 Created (`correct: true`)**. Varian `picoCTF{...}` ditolak validator (`correct: false`).

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_194_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (563/563 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_245`: **PASS** (reproduksi ekstraksi kredensial hardcoded & XOR stream exit 0, token terverifikasi cocok).
3. `solve_246`: **PASS** (reproduksi deobfuskasi ASCII ordinal heksadesimal exit 0, token terverifikasi cocok).
4. `solve_247`: **PASS** (reproduksi serangan kamus pre-image hash MD5 RFC 1321 exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/Beginner-picoMini-2022/`).
