# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 195

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (248, 249, 250). Kelanjutan Audit Event Beginner picoMini 2022 (12/13 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 195 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint kelanjutan event Beginner picoMini 2022 (#248, #249, #250), kepatuhan NIST SP 800-115, dan integrasi repositori |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan seri password cracking dan eksekusi skrip (#248 PW Crack 4, #249 PW Crack 5, #250 runme.py) pada event `Beginner picoMini 2022` untuk audit standar LKS |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kelemahan algoritma hashing MD5 tanpa garam (CWE-327 / RFC 1321), eskalasi ruang kunci serangan kamus 100 entri hingga enumerasi tuntas 65.536 kombinasi (CWE-521 / NIST SP 800-115 § 5), dan risiko kredensial hardcoded pada skrip runtime (CWE-798) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Mengoptimasi skrip solver `solve_248`, `solve_249`, `solve_250` dengan mode reproduksi offline deterministik (embedded hash/enc/script) serta membangun suite uji test harness `test_batch_195_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 564/564 skrip Python tanpa regresi, pengujian wrapper matrix (academy vs picoCTF), dan validasi JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun materi kurikulum bimbingan teknis LKS Cyber Security: mitigasi kelemahan autentikasi kata sandi, batas komputasi pre-image hash MD5, serta SAST pre-commit scanning untuk mencegah kebocoran secret |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang dan siap digunakan pada VPS.
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_195_harness.py`.
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

### Modul 1: ID 248 `PW Crack 4` (General Skills, Medium, Beginner picoMini 2022)
- **Arsitektur & Batas Input:** Skrip Python `level4.py`, berkas hash intisari biner `level4.hash.bin` (16 bita), dan berkas cipher `level4.flag.txt.enc`.
- **Akar Kerentanan (CWE-327 / CWE-798 / NIST SP 800-115 § 5):**
  1. Skrip memperluas ruang pencarian kandidat kata sandi menjadi 100 entri string heksadesimal 4 karakter pada variabel `pos_pw_list`.
  2. Fungsi verifikasi bergantung pada hashing MD5 tanpa garam (salt).
  3. Serangan kamus otomatis menguji ke-100 kandidat dalam hitungan milidetik dan menemukan bahwa MD5("bb8e") cocok dengan target digest tersimpan.
  4. Dekripsi stream XOR modular menggunakan kunci `"bb8e"` memulihkan bendera pembelajaran.
- **Validasi Validator:** Submisi token `academy{fl45h_5pr1ng1ng_c1e14a37}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 249 `PW Crack 5` (General Skills, Medium, Beginner picoMini 2022)
- **Arsitektur & Batas Input:** Skrip Python `level5.py`, berkas hash biner `level5.hash.bin` (16 bita), berkas cipher `level5.flag.txt.enc`, dan berkas kamus eksternal `dictionary.txt` memuat seluruh 65.536 kombinasi 4 digit heksadesimal (`0000` hingga `ffff`).
- **Akar Kerentanan (CWE-327 / CWE-521 / NIST SP 800-115 § 5):**
  1. Pembatasan kata sandi pada ruang 4 digit heksadesimal menghasilkan ruang kunci yang sangat sempit ($16^4 = 65.536$).
  2. Ketiadaan fungsi hash lambat (seperti Argon2 atau bcrypt) memungkinkan serangan kamus tuntas (*exhaustive keyspace enumeration*) diselesaikan dalam waktu kurang dari 50 milidetik pada CPU modern.
  3. Pencarian pre-image menemukan kecocokan pada kata sandi `"7e5f"`.
  4. Dekripsi stream XOR modular pada ciphertext dengan kunci `"7e5f"` menghasilkan bendera resmi.
- **Validasi Validator:** Submisi token `academy{h45h_sl1ng1ng_e062d0ff}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 250 `runme.py` (General Skills, Easy, Beginner picoMini 2022)
- **Arsitektur & Batas Input:** Skrip Python mandiri `runme.py` yang disediakan melalui unduhan repositori berkas CyLab.
- **Akar Kerentanan (CWE-798 / NIST SP 800-115 § 4.2):**
  1. Konstanta bendera disematkan langsung (*hardcoded secret*) pada level modul: `flag = 'academy{run_s4n1ty_run}'`.
  2. Ketiadaan kontrol akses atau transformasi kriptografis memungkinkan ekstraksi instan melalui eksekusi interpreter `python3 runme.py`, parsing regex, atau penelusuran Abstract Syntax Tree (AST).
- **Validasi Validator:** Submisi token `academy{run_s4n1ty_run}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_195_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (564/564 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_248`: **PASS** (reproduksi serangan kamus 100 kandidat & dekripsi XOR exit 0, token terverifikasi cocok).
3. `solve_249`: **PASS** (reproduksi enumerasi tuntas 65.536 kunci & dekripsi XOR exit 0, token terverifikasi cocok).
4. `solve_250`: **PASS** (reproduksi inspeksi statis AST / eksekusi skrip Python exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/Beginner-picoMini-2022/`).
