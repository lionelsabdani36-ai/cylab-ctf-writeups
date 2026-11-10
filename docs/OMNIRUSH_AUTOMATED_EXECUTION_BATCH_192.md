# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 192

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 §4.2 (analisis kerentanan), §4.3 (validasi terkontrol), §4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (238, 239, 240). Inisiasi Audit Event Beginner picoMini 2022 (3/13 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 192 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin inisiasi audit sprint event Beginner picoMini 2022 (#238, #239, #240), kepatuhan NIST SP 800-115, dan integrasi repositori |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul backlog awal pada event `Beginner picoMini 2022` yang memerlukan audit standar LKS dan verifikasi wrapper platform |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kegagalan isolasi materi kunci XOR teks polos (CWE-312/CWE-798), client-side authorization gate bypass pada kuis konversi basis (CWE-807), dan kesalahan tata bahasa indentasi Python (PEP 8 / CWE-398) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Memperbarui skrip solver `solve_238`, `solve_239`, `solve_240` dengan mode reproduksi offline deterministik dan membangun suite uji test harness `test_batch_192_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi live `POST /api/submissions/` dengan CSRF token, sweep AST 561/561 skrip Python tanpa regresi, dan validasi JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun materi kurikulum LKS: secret management (Vault/KMS), pemisahan logika proteksi vs presentasi, dan integrasi SAST linter pada CI/CD |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada VPS.
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_192_harness.py`.
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

### Modul 1: ID 238 `Codebook` (General Skills, Easy, Beginner picoMini 2022)
- **Arsitektur & Batas Input:** Skrip Python `code.py` dan berkas buku sandi teks polos `codebook.txt`.
- **Akar Kerentanan (CWE-312 / CWE-326 / CWE-798):**
  1. Skrip menerapkan enkripsi simetris XOR berulang (*repeating-key XOR*), namun seluruh materi pembangkit kunci dan ciphertext didistribusikan dalam teks terang (*cleartext*).
  2. Nilai ciphertext `flag_enc` didefinisikan sebagai 33 literal `chr(...)` di dalam skrip.
  3. Berkas pendamping `codebook.txt` menyimpan string tetap `azbycxdwevfugthsirjqkplomn`. Pemetaan indeks `[4, 14, 13, 14, 23, 25, 16, 0, 25]` secara deterministik menghasilkan string kunci `chthonian`.
  4. Sifat involutori XOR memungkinkan dekripsi instan tanpa interaksi runtime.
- **Validasi Validator:** Submisi token `academy{c0d3b00k_455157_570b049a}` menghasilkan **HTTP 201 Created (`correct: true`)**. Varian `picoCTF{...}` ditolak validator (`correct: false`).

### Modul 2: ID 239 `convertme.py` (General Skills, Easy, Beginner picoMini 2022)
- **Arsitektur & Batas Input:** Skrip Python interaktif `convertme.py` yang menanyakan konversi bilangan desimal ke biner.
- **Akar Kerentanan (CWE-807 / CWE-312 / CWE-798):**
  1. Program mengkondisikan rilis flag pada pemeriksaan sisi klien `ans_num == num`.
  2. Nilai `flag_enc` (32 karakter) dan kunci XOR `'enkidu'` tertanam langsung dalam skrip.
  3. Pemeriksaan input dapat diabaikan sepenuhnya; pemanggilan `str_xor(flag_enc, 'enkidu')` secara statis menghasilkan bendera plaintext.
- **Validasi Validator:** Submisi token `academy{4ll_y0ur_b4535_fff0af3d}` menghasilkan **HTTP 201 Created (`correct: true`)**. Varian `picoCTF{...}` ditolak validator (`correct: false`).

### Modul 3: ID 240 `fixme1.py` (General Skills, Easy, Beginner picoMini 2022)
- **Arsitektur & Batas Input:** Skrip Python `fixme1.py` dengan galat sintaksis tingkat tata bahasa (*IndentationError*).
- **Akar Kerentanan (CWE-398 / CWE-312 / CWE-798):**
  1. Pernyataan `print('That is correct! Here\'s your flag: ' + flag)` memiliki 2 karakter spasi ekstra di luar blok kontrol apapun, memicu `IndentationError: unexpected indent` sesuai aturan tata bahasa Python PEP 8 / Language Reference §2.1.8.
  2. Menghapus indentasi spasi ekstra menormalkan pohon sintaks abstrak (AST) dan mengizinkan kompilasi.
  3. Ciphertext `flag_enc` (34 karakter) dan kunci statis `'enkidu'` terpapar teks terang, menghasilkan flag langsung setelah dieksekusi.
- **Validasi Validator:** Submisi token `academy{1nd3nt1ty_cr1515_f63757ad}` menghasilkan **HTTP 201 Created (`correct: true`)**. Varian `picoCTF{...}` ditolak validator (`correct: false`).

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_192_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (561/561 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_238`: **PASS** (reproduksi key schedule inversion & XOR exit 0, token terverifikasi cocok).
3. `solve_239`: **PASS** (reproduksi radix transformation & static XOR exit 0, token terverifikasi cocok).
4. `solve_240`: **PASS** (reproduksi AST syntax indentation remediation exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/Beginner-picoMini-2022/`).
