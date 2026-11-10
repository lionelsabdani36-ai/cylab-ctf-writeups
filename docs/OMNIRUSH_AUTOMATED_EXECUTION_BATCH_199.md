# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 199

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (260, 261, 262). Kelanjutan Event picoCTF 2022 (11/65 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 199 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 199, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian tuntas 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan event picoCTF 2022 (#260 buffer overflow 3, #261 credstuff, #262 CVE-XXXX-XXXX), memverifikasi ketersediaan artefak biner ELF, leak archive, dan spesifikasi CVE Windows Print Spooler |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan peretasan custom userland canary byte-by-byte (CWE-121 / CWE-697), pengabaian sanitasi kebocoran kredensial (CWE-256 / CWE-327 / OAT-008), dan analisis arsitektur RPC Windows Print System RCE PrintNightmare (CWE-269 / CVE-2021-34527) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Mengembangkan dan merektifikasi skrip solver mandiri `solve_260_buffer_overflow_3.py`, `solve_261_credstuff.py` (rektifikasi ROT13 token validator), `solve_262_cve.py`, serta membangun suite uji deterministik `test_batch_199_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 568/568 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform (HTTP 201 correct:true), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: analisis tata letak bingkai tumpukan memori (stack layout) dengan canary buatan, pengamanan penyimpanan kata sandi berbasis Argon2id/bcrypt, mitigasi PrintNightmare via GPO dan pembatasan RPC Print Spooler |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang dan siap digunakan pada VPS.
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_199_harness.py`.
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

### Modul 1: ID 260 `buffer overflow 3` (Binary Exploitation, Hard, picoCTF 2022)
- **Arsitektur & Batas Input:** Biner ELF 32-bit x86 tanpa GCC Stack Canary dan tanpa PIE (`0x08048000`). Pengembang mengimplementasikan custom stack canary 4 bita berbasis file statis `canary.txt`. Program menanyakan panjang `count` lalu membaca `read(0, buf, count)` ke dalam buffer 64 bita tanpa validasi batas atas.
- **Akar Kerentanan (CWE-121 / CWE-697 / NIST SP 800-115 § 4.2):**
  1. `count` tidak dibatasi pada ukuran `buf` 64 bita, memungkinkan luapan memori linier ke canary dan saved EIP.
  2. Nilai canary statis tidak berubah antar koneksi karena dimuat dari file `canary.txt` yang sama.
  3. Umpan balik program membedakan kegagalan canary ("Stack Smashing Detected") dengan kelanjutan program ("Ok... Now Where's the Flag?"), membentuk oracle boolean linier. Penyerang dapat menebak nilai 4 bita secara bertahap dalam $4 \times 256 = 1.024$ percobaan alih-alih $256^4 \approx 4{,}29 \times 10^9$.
  4. Setelah canary `BiRd` ditemukan, muatan 64 bita junk + 4 bita canary + 16 bita padding alignment + alamat `win()` (`0x08049236`) dialirkan untuk membajak alur kontrol.
- **Validasi Validator:** Submisi token `academy{Stat1C_c4n4r13s_4R3_b4D_ceaa3353}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 261 `credstuff` (Cryptography, Easy, picoCTF 2022)
- **Arsitektur & Batas Input:** Berkas arsip `leak.tar` berisi basis data teks kredensial pasar gelap dengan ratusan baris paralel (`usernames.txt` dan `passwords.txt`). Akun target `cultiris` terletak pada baris 378 dengan kata sandi tersandi `npnqrzl{P7e1S_54I35_71Z3}`.
- **Akar Kerentanan (CWE-256 / CWE-327 / OAT-008 / NIST SP 800-115 § 4.2):**
  1. Kata sandi disimpan dalam skema tersandi reversibel monoalfabetik rotasi 13 langkah (ROT13) tanpa pengacakan kunci (*zero key entropy*).
  2. Prefiks `npnqrzl` secara langsung mendekripsi ke `academy`, mengonfirmasi format token.
  3. Evaluasi ROT13 murni menghasilkan token persis `academy{C7r1F_54V35_71M3}`. Penemuan audit membuktikan validator CyLab live menerima token ini dengan status `correct: true`, merektifikasi catatan versi usang sebelumnya.
- **Validasi Validator:** Submisi token `academy{C7r1F_54V35_71M3}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 262 `CVE-XXXX-XXXX` (Binary Exploitation, Easy, picoCTF 2022)
- **Arsitektur & Batas Input:** Tantangan riset intelijen ancaman siber kerentanan sistem operasi Windows Print Spooler (`spoolsv.exe`). Ditanyakan pengidentifikasi CVE resmi untuk kerentanan remote code execution (RCE) pertama pada tahun 2021, dengan pengecualian kerentanan Local Spooler.
- **Akar Kerentanan (CWE-269 / CWE-829 / CVE-2021-34527 / NIST SP 800-115 § 4.2):**
  1. Fungsi RPC `RpcAddPrinterDriverEx` pada protokol `[MS-RPRN]` gagal memvalidasi hak akses pemanggil saat mendaftarkan driver printer baru dan memuat pustaka DLL dari jalur remote SMB sembarang (`\\attacker\share\payload.dll`).
  2. Eksekusi kode terjadi di bawah konteks hak istimewa tertinggi `NT AUTHORITY\SYSTEM`.
  3. Disambiguasi ancaman membedakan CVE-2021-1675 (LPE lokal) dengan CVE-2021-34527 (RCE kritis berjuluk PrintNightmare dengan CVSS 8.8) yang dirilis dengan pembaruan darurat *out-of-band* pada Juli 2021.
- **Validasi Validator:** Submisi token `academy{CVE-2021-34527}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_199_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (568/568 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_260`: **PASS** (reproduksi stack canary oracle bypass & ret2win exit 0, token terverifikasi cocok).
3. `solve_261`: **PASS** (reproduksi credential stuff extraction & ROT13 cipher exit 0, token terverifikasi cocok).
4. `solve_262`: **PASS** (reproduksi vulnerability research CVE PrintNightmare exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/picoCTF-2022/`).
