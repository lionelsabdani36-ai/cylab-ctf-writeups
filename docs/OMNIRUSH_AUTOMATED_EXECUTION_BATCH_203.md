# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 203

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (273, 274, 275). Kelanjutan Event picoCTF 2022 (23/65 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 203 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 203, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian tuntas 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan event picoCTF 2022 (#273 GDB Test Drive, #274 Includes, #275 Inspect HTML), memverifikasi artefak biner ELF 64-bit gdbme, dokumen web HTML dengan linked assets (style.css & script.js), serta web page static comments |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan manipulasi register penunjuk instruksi ($rip) dan sleep stall bypass (CWE-215 / NIST SP 800-115 § 4.3), serta paparan data rahasia melalui komentar aset eksternal dan pohon DOM HTML (CWE-615 / OWASP A05) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekayasa dan memperbarui skrip solver otomatis mandiri `solve_273_gdb_test_drive.py`, `solve_274_includes.py`, dan `solve_275_inspect_html.py`, serta membangun suite uji deterministik `test_batch_203_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 572/572 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform (HTTP 201 correct:true), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: teknik manipulasi alur eksekusi biner dinamis tanpa patching disk, serta metodologi enumerasi aset web eksternal komprehensif pada modul Web Security |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada lingkungan VPS (`lionelsabdani36@gmail.com`).
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_203_harness.py`.
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

### Modul 1: ID 273 `GDB Test Drive` (Reverse Engineering, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Biner ELF 64-bit Linux PIE (`gdbme`, unstripped). Program menunda eksekusi melalui panggilan sistem `sleep(0x186a0)` (100.000 detik) pada offset `main+99` sebelum mencapai fungsi pencetakan flag `rotate_encrypt`.
- **Akar Kerentanan (CWE-215 / NIST SP 800-115 § 4.3):**
  1. Ketiadaan proteksi anti-debugging memungkinkan pelekatan debugger GDB via antarmuka kernel `ptrace`.
  2. Alur instruksi dapat dimanipulasi dengan menyetel breakpoint di `*(main+99)` dan mengarahkan penunjuk instruksi `$rip` secara dinamis ke `*(main+104)` via perintah `jump *(main+104)`.
  3. Biner memuat 4 nilai konstanta 64-bit ke stack yang didekripsi via algoritma ROT47 (`rotate_encrypt`).
- **Validasi Validator:** Submisi token `academy{d3bugg3r_dr1v3_4cc75120}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 274 `Includes` (Web Exploitation, Easy, picoCTF 2022)
- **Arsitektur & Batas Input:** Aplikasi web statis menyajikan dokumen HTML yang menautkan stylesheet eksternal `style.css` dan skrip klien `script.js`.
- **Akar Kerentanan (CWE-615 / OWASP A05 / NIST SP 800-115 § 4.3):**
  1. Aset eksternal web disajikan apa adanya tanpa proses minifikasi atau pembersihan komentar (*comment stripping*).
  2. Komentar CSS `/* academy{1nclu51v17y_1of2_ */` dan komentar JS `// f7w_2of2_ce526b3b}` membocorkan pecahan token rahasia secara publik.
  3. Penggabungan kedua segmen membentuk token valid tanpa memerlukan hak istimewa pengguna.
- **Validasi Validator:** Submisi token `academy{1nclu51v17y_1of2_f7w_2of2_ce526b3b}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 275 `Inspect HTML` (Web Exploitation, Easy, picoCTF 2022)
- **Arsitektur & Batas Input:** Dokumen web statis menyajikan teks kutipan sejarah.
- **Akar Kerentanan (CWE-615 / OWASP A05 / NIST SP 800-115 § 4.3):**
  1. Komentar HTML `<!-- ... -->` diparse ke dalam pohon DOM peramban web dan dikirimkan dalam bentuk teks jelas (*cleartext*).
  2. Pengembang meninggalkan string rahasia `<!--academy{1n5p3t0r_0f_h7ml_cdc35adf}-->` tepat sebelum penutup tag `</body>`.
  3. Inspeksi kode sumber pasif (*passive source reconnaissance*) langsung mengungkap token resmi.
- **Validasi Validator:** Submisi token `academy{1n5p3t0r_0f_h7ml_cdc35adf}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_203_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (572/572 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_273`: **PASS** (reproduksi live GDB instruction jump & static ROT47 exit 0, token cocok).
3. `solve_274`: **PASS** (reproduksi live CSS/JS asset comment carving exit 0, token cocok).
4. `solve_275`: **PASS** (reproduksi HTML DOM comment inspection exit 0, token cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/picoCTF-2022/`, zero em dash).
