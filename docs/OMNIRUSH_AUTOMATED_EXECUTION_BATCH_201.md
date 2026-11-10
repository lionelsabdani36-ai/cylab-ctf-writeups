# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 201

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (267, 268, 269). Kelanjutan Event picoCTF 2022 (17/65 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 201 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 201, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian tuntas 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan event picoCTF 2022 (#267 file-run2, #268 File types, #269 flag leak), memverifikasi ketersediaan artefak biner ELF 64-bit, berkas arsip terenkapsulasi Flag.pdf, dan socket TCP layanan biner x86 |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan passing argumen CLI POSIX dan hardcoded credentials (CWE-312 / CWE-798), penyamaran ekstensi berkas arsip bertingkat 10 lapis (CWE-434 / CWE-20), dan format string vulnerability pada biner 32-bit (CWE-134 / RFC POSIX printf) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekayasa dan memperbarui skrip solver otomatis mandiri `solve_268_file_types.py` (otomasi ekstraksi shar/uu/ar/cpio/bzip2/gzip/lzip/lz4/lzma/lzop/xz), memvalidasi `solve_267_file_run2.py` dan `solve_269_flag_leak.py`, serta membangun suite uji deterministik `test_batch_201_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 570/570 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform (HTTP 201 correct:true), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: metodologi Binary Reverse Engineering (argc/argv disassembly), media analysis & recursive decompression, serta pencegahan eksploitasi format string via compiler hardening flags |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada lingkungan VPS (`lionelsabdani36@gmail.com`).
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_201_harness.py`.
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

### Modul 1: ID 267 `file-run2` (Reverse Engineering, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Biner eksekutabel ELF 64-bit x86-64 unstripped dynamically linked berukuran 16,080 bytes (`run`). Target memvalidasi jumlah argumen baris perintah POSIX (`argc`) dan nilai argumen pertama (`argv[1]`).
- **Akar Kerentanan (CWE-312 / CWE-798 / NIST SP 800-115 § 5.3):**
  1. Validasi masukan menguji `argc == 2` dan membandingkan `argv[1]` terhadap string statis `"Hello!"` menggunakan `strcmp`.
  2. Konstanta string token bendera dan string pembanding disimpan dalam bentuk teks terbuka di segmen memori baca-saja tanpa enkripsi atau teknik anti-tampering.
  3. Token dapat dipulihkan secara instan melalui ekstraksi statis ekspresi reguler pada segmen biner maupun eksekusi dinamis dengan menyuplai argumen `./run Hello!`.
- **Validasi Validator:** Submisi token `academy{F1r57_4rgum3n7_3819dbe5}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 268 `File types` (Forensics, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Berkas artefak `Flag.pdf` (~5.1 KB) disamarkan sebagai berkas PDF padahal struktur internalnya merupakan Shell Archive (shar) Unix yang mengenkapsulasi rantai kompresi 10 lapis.
- **Akar Kerentanan (CWE-434 / CWE-20 / NIST SP 800-115 § 5.2):**
  1. Ketergantungan sistem pada ekstensi penamaan alih-alih identifikasi magic bytes biner memungkinkan penyamaran tipe berkas berbahaya (extension spoofing).
  2. Rantai enkapsulasi kompresi bertingkat: GNU Shell Archive -> UUEncode -> Unix `ar` -> Binary CPIO (magic 070707 LE) -> Bzip2 -> Gzip (RFC 1952) -> Lzip (LZMA1 RAW) -> LZ4 Frame -> LZMA ALONE -> Lzop (LZO) -> Lzip -> XZ -> Hex ASCII.
  3. Penguraian deterministik berurutan mengekstrak dua baris heksadesimal yang dikonversi ke token ASCII.
- **Validasi Validator:** Submisi token `academy{f1len@m3_m@n1pul@t10n_f0r_0b2cur17y_35957b68}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 269 `flag leak` (Binary Exploitation, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Biner ELF 32-bit x86 interaktif (`vuln`). Program membaca berkas `flag.txt` ke dalam buffer frame stack fungsi `vuln()` via `readflag(flag, 64)`, kemudian menerima string masukan pengguna ke dalam `story[128]` via `scanf("%127s", story)`.
- **Akar Kerentanan (CWE-134 / NIST SP 800-115 § 5.3):**
  1. Pemanggilan `printf(story)` mengevaluasi string masukan pengguna secara langsung sebagai parameter format specifier (Format String Vulnerability).
  2. Pada arsitektur 32-bit x86 cdecl, parameter fungsi diteruskan melalui memori stack. Penentu format posisional `%{k}$s` memperlakukan nilai 4 bita pada slot stack ke-k sebagai pointer `char *` dan mendereferensikannya.
  3. Pada offset stack indeks 20, pointer merujuk langsung ke buffer `flag`, sehingga format specifier `%20$s` membocorkan seluruh isi token rahasia tanpa merusak alur kontrol eksekusi.
- **Validasi Validator:** Submisi token `academy{L34k1ng_Fl4g_0ff_St4ck_0845a0aa}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_201_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (570/570 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_267`: **PASS** (reproduksi live ELF binary inspection & dynamic argument pass exit 0, token cocok).
3. `solve_268`: **PASS** (reproduksi multi-stage nested compression archive decompression exit 0, token cocok).
4. `solve_269`: **PASS** (reproduksi positional format string dereference %20$s exit 0, token cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/picoCTF-2022/`).
