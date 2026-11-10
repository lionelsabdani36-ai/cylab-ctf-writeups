# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 193

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 §4.2 (analisis kerentanan), §4.3 (validasi terkontrol), §4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (241, 242, 243). Kelanjutan Audit Event Beginner picoMini 2022 (6/13 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 193 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint kelanjutan event Beginner picoMini 2022 (#241, #242, #243), kepatuhan NIST SP 800-115, dan integrasi repositori |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan pada event `Beginner picoMini 2022` yang memerlukan audit standar LKS dan verifikasi wrapper platform |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kebingungan semantik operator penugasan vs perbandingan (CWE-480/CWE-398), risiko eksekusi kode klien akibat format ekspresi string output (CWE-116/CWE-95), dan analisis kerapuhan algoritma hash MD5 serta kontrol batas waktu interaktif (RFC 1321/CWE-799) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Memperbarui skrip solver `solve_241`, `solve_242`, `solve_243` dengan mode reproduksi offline deterministik dan membangun suite uji test harness `test_batch_193_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi live `POST /api/submissions/` dengan CSRF token, sweep AST 562/562 skrip Python tanpa regresi, dan validasi JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun materi kurikulum LKS: safe expression parsing (zero eval), otomasi soket jaringan interaktif di bawah batas waktu ketat, dan migrasi algoritma hash kriptografis ke standar modern (SHA-256) |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada VPS.
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_193_harness.py`.
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

### Modul 1: ID 241 `fixme2.py` (General Skills, Easy, Beginner picoMini 2022)
- **Arsitektur & Batas Input:** Skrip Python `fixme2.py` dengan galat sintaksis operator penugasan di dalam klausa kondisional `if`.
- **Akar Kerentanan (CWE-480 / CWE-398 / CWE-312 / CWE-798):**
  1. Baris `if flag = "":` menggunakan operator penugasan `=` alih-alih operator perbandingan kesetaraan `==`, memicu pengecualian fatal `SyntaxError: invalid syntax` saat parser menyusun AST.
  2. Mengganti operator menjadi `==` memulihkan integritas AST kode.
  3. Nilai `flag_enc` (41 karakter) dan kunci XOR `'enkidu'` tertanam langsung dalam teks polos, memungkinkan pemulihan bendera secara offline tanpa interaksi runtime.
- **Validasi Validator:** Submisi token `academy{3qu4l1ty_n0t_4551gnm3nt_ad29eab9}` menghasilkan **HTTP 201 Created (`correct: true`)**. Varian `picoCTF{...}` ditolak validator (`correct: false`).

### Modul 2: ID 242 `Glitch Cat` (General Skills, Easy, Beginner picoMini 2022)
- **Arsitektur & Batas Input:** Layanan TCP socket interaktif (RFC 9293) yang mengirimkan ekspresi string Python terpecah dengan pemanggilan fungsi konversi kode karakter ordinal ASCII heksadesimal `chr(0x..)`.
- **Akar Kerentanan (CWE-116 / CWE-95 / RFC 20):**
  1. Layanan menghasilkan string sintaksis Python executable: `'academy{gl17ch_m3_n07_' + chr(0x33) + ... + '}'`.
  2. Klien naif rentan mengeksekusi fungsi dinamis berbahaya seperti `eval()`.
  3. Rekonstruksi defensif yang aman menerapkan ekstraksi regex terhadap nilai heksadesimal ordinal `[0x33, 0x38, 0x38, 0x31, 0x64, 0x63, 0x65, 0x33]` yang berkorespondensi langsung dengan karakter ASCII `3881dce3`.
- **Validasi Validator:** Submisi token `academy{gl17ch_m3_n07_3881dce3}` menghasilkan **HTTP 201 Created (`correct: true`)**. Varian `picoCTF{...}` ditolak validator (`correct: false`).

### Modul 3: ID 243 `HashingJobApp` (General Skills, Easy, Beginner picoMini 2022)
- **Arsitektur & Batas Input:** Layanan TCP socket interaktif (RFC 9293) yang menguji perhitungan intisari hash MD5 (RFC 1321) secara beruntun di bawah batas waktu timeout yang sangat ketat.
- **Akar Kerentanan (CWE-799 / RFC 1321):**
  1. Batas waktu respons yang sempit dan string acak pada setiap putaran membuat komputasi manual manusia tidak mungkin berhasil.
  2. Dibangun otomasi skrip klien soket interaktif yang menangkap teks dalam tanda kutip, menghitung intisari MD5 128-bit secara real-time, dan mengembalikan respon newline-terminated hingga 3 putaran selesai.
  3. Layanan kemudian mengembalikan token resmi bendera penawaran kerja.
- **Validasi Validator:** Submisi token `academy{4ppl1c4710n_r3c31v3d_467e06bf}` menghasilkan **HTTP 201 Created (`correct: true`)**. Varian `picoCTF{...}` ditolak validator (`correct: false`).

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_193_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (562/562 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_241`: **PASS** (reproduksi AST operator remediation & XOR exit 0, token terverifikasi cocok).
3. `solve_242`: **PASS** (reproduksi safe regex ASCII evaluation exit 0, token terverifikasi cocok).
4. `solve_243`: **PASS** (reproduksi RFC 1321 MD5 socket automation exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/Beginner-picoMini-2022/`).
