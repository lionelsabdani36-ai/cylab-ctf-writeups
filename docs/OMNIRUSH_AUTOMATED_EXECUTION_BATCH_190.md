# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 190

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 §4.2 (analisis kerentanan), §4.3 (validasi terkontrol), §4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (87, 88, 91).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 190 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin inisiasi audit sprint event picoCTF 2020 Mini-Competition (#87, #88, #91), kepatuhan NIST SP 800-115, dan integrasi repositori |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul backlog pada event `picoCTF 2020 Mini-Competition` yang memerlukan re-audit standar LKS dan verifikasi wrapper platform |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis residu alokasi ext3 file slack space (CWE-226), injeksi SQL SQLite evasif multi-tahap (CWE-89/184), dan paparan data teks polos pada repositori CDN (CWE-319/200) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Memperbarui skrip solver `solve_87`, `solve_88`, `solve_91` dengan parser otomatis dan membangun suite uji test harness deterministik `test_batch_190_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi live `POST /api/submissions/` dengan CSRF token, sweep AST 559/559 skrip Python tanpa regresi, dan validasi JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun materi kurikulum LKS: media sanitization NIST SP 800-88, parameterized queries SQLite PDO, dan kebijakan akses penyimpanan objek awan (cloud bucket security) |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada VPS.
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_190_harness.py`.
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

### Modul 1: ID 87 `pitter-patter-platters` (Forensics, Medium, picoCTF 2020 Mini-Competition)
- **Arsitektur & Batas Input:** Berkas citra disk `suspicious.dd.sda1` (32 MB ext3 filesystem). Inode 12 `suspicious-file.txt` berukuran logis 55 byte berada pada blok fisik 2049 (ukuran blok 4096 byte).
- **Akar Kerentanan (CWE-226 / CWE-312):** Residual slack space seluas $4096 - 55 = 4041$ byte pada blok 2049 tidak dibersihkan saat penulisan berkas. Penulis menyembunyikan flag dalam format karakter UTF-16LE terbalik (`}\x00e\x001\x00...`). Mengekstrak byte slack, mendekode UTF-16LE, dan membalikkan string menghasilkan `academy{b3_5t111_mL|_<3_d18a1e1e}`.
- **Validasi Validator:** Submisi token `academy{b3_5t111_mL|_<3_d18a1e1e}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `picoCTF{...}` ditolak dengan `correct: false`.

### Modul 2: ID 88 `web-gauntlet` (Web Exploitation, Medium, picoCTF 2020 Mini-Competition)
- **Arsitektur & Batas Input:** Aplikasi web PHP dengan backend SQLite3 menyajikan 5 putaran autentikasi login dengan filter blacklist dinamis pada parameter `user` dan `pass`.
- **Akar Kerentanan (CWE-89 / CWE-184):** Penggabungan string langsung ke kueri SQL. Filter kata kunci blacklist dapat dihindari melalui sintaks spesifik SQLite: komentar blok C-style `/*` untuk mengabaikan password tanpa spasi, serta operator penggabungan string `||` (`admi'||'n'/*`) untuk merekonstruksi kata `admin` tanpa terdeteksi filter harfiah. Menyelesaikan 5 putaran mengungkap flag pada `/filter.php`.
- **Validasi Validator:** Submisi token `academy{y0u_m4d3_1t_ecb312a6}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `picoCTF{...}` ditolak dengan `correct: false`.

### Modul 3: ID 91 `nothing-up-my-sleeve` (General Skills, Medium, picoCTF 2020 Mini-Competition)
- **Arsitektur & Batas Input:** Aset teks statis `flag.txt` dihosting secara publik pada CDN CyLab Academy (`challenge-files.cylabacademy.net/library/...`).
- **Akar Kerentanan (CWE-319 / CWE-200):** Paparan data sensitif teks polos tanpa pembatasan kontrol akses pada objek publik. Aset diunduh via HTTPS (RFC 9110/RFC 2818) menggunakan utilitas CLI `curl`/`wget`. Integritas berkas divalidasi menggunakan ringkasan SHA-256 `ebf2774283940b9a69962376466e18a84efee6daa9cb8feb8d325b67254205dd` (RFC 6234), menghasilkan flag `academy{c0ngr4ts_0n_y0ur_s4n1ty}`.
- **Validasi Validator:** Submisi token `academy{c0ngr4ts_0n_y0ur_s4n1ty}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `picoCTF{...}` ditolak dengan `correct: false`.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_190_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (559/559 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_87`: **PASS** (reproduksi ekstraksi ext3 slack space UTF-16LE exit 0, token terverifikasi cocok).
3. `solve_88`: **PASS** (reproduksi injeksi SQLite multi-round evasion exit 0, token terverifikasi cocok).
4. `solve_91`: **PASS** (reproduksi pengunduhan dan verifikasi hash SHA-256 exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/picoCTF-2020-Mini-Competition/`).
