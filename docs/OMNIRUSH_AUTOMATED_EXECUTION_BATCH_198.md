# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 198

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (257, 258, 259). Kelanjutan Event picoCTF 2022 (8/65 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 198 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 198, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian tuntas 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan event picoCTF 2022 (#257 buffer overflow 0, #258 buffer overflow 1, #259 buffer overflow 2), memverifikasi ketersediaan artefak biner ELF dan layanan interaktif TCP |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan stack buffer overflow (CWE-121 / CWE-676), mekanisme penanganan sinyal SIGSEGV, pembajakan return pointer %eip, dan manipulasi konvensi pemanggilan cdecl 32-bit (System V i386 ABI) dengan passing argumen pada stack |
| Alex (fullstack-dev) | Solver Remediation & Harness | Mengembangkan dan membakukan skrip solver mandiri `solve_257`, `solve_258`, `solve_259` dengan struktur terstandarisasi serta membangun suite uji deterministik `test_batch_198_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 567/567 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform, dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: analisis tata letak bingkai tumpukan memori (stack layout), pembongkaran biner disassembli objdump/GDB, mitigasi kompilasi (Canaries, PIE, ASLR, Full RELRO), dan remediasi secure coding |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang dan siap digunakan pada VPS.
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_198_harness.py`.
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

### Modul 1: ID 257 `buffer overflow 0` (Binary Exploitation, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Biner ELF 32-bit x86 tanpa stack canary. Masukan awal ditampung dalam buffer 100 byte via `gets(buf1)` lalu disalin ke buffer lokal 16 byte via `strcpy(buf2, input)`.
- **Akar Kerentanan (CWE-121 / CWE-676 / NIST SP 800-115 § 4.2):**
  1. `strcpy()` menyalin deretan byte tanpa pemeriksaan batas ukuran array tujuan (`buf2[16]`).
  2. Input 32 karakter meluap melewati buffer lokal, merusak saved %ebp dan return pointer %eip.
  3. Kembalinya fungsi `vuln()` memicu page fault / pelanggaran segmentasi. Kernel mengirimkan sinyal SIGSEGV (Signal 11).
  4. Rutin handler sinyal terdaftar `sigsegv_handler` menangkap sinyal dan mencetak isi bendera langsung ke stdout.
- **Validasi Validator:** Submisi token `academy{ov3rfl0ws_ar3nt_that_bad_1e25e28f}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 258 `buffer overflow 1` (Binary Exploitation, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Biner ELF 32-bit x86 tanpa Stack Canary dan tanpa PIE. Membaca masukan ke dalam buffer lokal 32 byte via `gets(buf)`.
- **Akar Kerentanan (CWE-121 / CWE-676 / NIST SP 800-115 § 4.2):**
  1. Jarak dari awal buffer lokal menuju saved frame pointer `%ebp` adalah 40 byte (`ebp - 0x28`).
  2. Saved return address `%eip` berada tepat pada offset 44 byte dari awal buffer.
  3. Alamat fungsi target `win()` bersifat statis dan deterministik di `0x080491E6`.
  4. Menyisipkan 44 byte padding diikuti alamat little-endian `\xe6\x91\x04\x08` membajak %eip langsung ke `win()`, yang membaca dan mencetak bendera.
- **Validasi Validator:** Submisi token `academy{addr3ss3s_ar3_3asy_b53c45d8}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 259 `buffer overflow 2` (Binary Exploitation, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Biner ELF 32-bit x86 tanpa Canary dan tanpa PIE. Membaca masukan ke buffer 100 byte via `gets(buf)`. Fungsi kemenangan `win(arg1, arg2)` memvalidasi `arg1 == 0xCAFEF00D` dan `arg2 == 0xF00DF00D`.
- **Akar Kerentanan (CWE-121 / CWE-676 / NIST SP 800-115 § 4.2):**
  1. Disassembli menunjukkan buffer masukan dialokasikan pada `ebp - 0x6c` (108 byte sebelum saved %ebp). Offset menuju return address %eip adalah 112 byte (108 + 4).
  2. Konvensi pemanggilan `cdecl` 32-bit menempatkan argumen pada stack tepat di atas return address:
     - Offset 112: Alamat target `win()` (`0x080491E6`)
     - Offset 116: Dummy return address dari `win()` (`0xDEADBEEF`)
     - Offset 120: Argumen 1 (`0xCAFEF00D`)
     - Offset 124: Argumen 2 (`0xF00DF00D`)
  3. Muatan eksploitasi mengelabui prolog `win()` sehingga kedua kondisi pembanding argumen terpenuhi dan bendera berhasil dicetak.
- **Validasi Validator:** Submisi token `academy{argum3nt5_4_d4yZ_0f3d7e91}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_198_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (567/567 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_257`: **PASS** (reproduksi stack smash pemicu SIGSEGV exit 0, token terverifikasi cocok).
3. `solve_258`: **PASS** (reproduksi pembajakan return pointer %eip offset 44 byte exit 0, token terverifikasi cocok).
4. `solve_259`: **PASS** (reproduksi ret2win cdecl stack arguments offset 112 byte exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/picoCTF-2022/`).
