# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 207

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (344, 345, 347). Inisiasi Audit Event picoCTF 2023 (3/42 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 207 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 207, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian sekuensial 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi inisiasi event picoCTF 2023 (#344 cancri-sp, #345 babygame01, #347 chrono), memverifikasi alur injeksi argumen browser Chromium headless, indexing array negatif 32-bit ELF, dan enumerasi crontab sistem |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan pemisahan kata shell unquoted variable expansion (CWE-88) & penyalahgunaan Chrome DevTools Protocol (CDP), out-of-bounds indexing array tumpukan (CWE-129 / CWE-787), serta kebocoran informasi pada file konfigurasi terjadwal berizin longgar (CWE-312 / CWE-200 / NIST SP 800-115 § 4.2) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekayasa dan memperbarui skrip solver otomatis mandiri `solve_344_cancri_sp.py`, `solve_345_babygame01.py`, dan `solve_347_chrono.py`, serta membangun suite uji deterministik `test_batch_207_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 576/576 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform (HTTP 201 correct:true), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: sanitasi parameter baris perintah shell POSIX, pencegahan integer underflow pada akses larik memori C/C++, dan metodologi audit konfigurasi terjadwal pasca-kompromi |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada lingkungan VPS (`lionelsabdani36@gmail.com`).
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_207_harness.py`.
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

### Modul 1: ID 344 `cancri-sp` (Web Exploitation, Hard, picoCTF 2023)
- **Arsitektur & Batas Input:** Layanan web bot otomasi browser dengan backend Node.js (`server.js`) dan pembungkus eksekusi shell (`run.sh`) yang meluncurkan patched Chromium browser dengan antarmuka MojoJS IPC.
- **Akar Kerentanan (CWE-88 / CWE-78 / NIST SP 800-115 § 4.2):**
  1. Ekspansi variabel `$1` tanpa tanda kutip ganda pada `run.sh` memicu pemisahan kata (*Word Splitting*) POSIX shell saat terdapat karakter spasi.
  2. Pengecekan prefiks sederhana `url.startsWith("http://")` di `server.js` mengizinkan penyisipan argumen baris perintah berbahaya ke biner `chrome`.
  3. Penyisipan parameter `--remote-debugging-port=9222` mengaktifkan antarmuka Chrome DevTools Protocol (CDP) lokal yang dapat dimanipulasi dari halaman web peretas untuk membuka skema berprivilese tinggi (`file:///challenge/`) dan mengekstrak token bendera rahasia.
- **Validasi Validator:** Submisi token `academy{11790d7c}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 345 `babygame01` (Binary Exploitation, Medium, picoCTF 2023)
- **Arsitektur & Batas Input:** Permainan labirin terminal berbasis ASCII grid $30 \times 90$ yang dikompilasi sebagai biner ELF 32-bit x86.
- **Akar Kerentanan (CWE-129 / CWE-787 / NIST SP 800-115 § 4.2):**
  1. Subrutin `move_player()` menghitung alamat sel larik secara dinamis (`map_base + row * 90 + col`) tanpa validasi batas bawah (`row >= 0`, `col >= 0`).
  2. Variabel status bendera `has_flag` dialokasikan pada stack di `ebp - 0xa9c`, tepat 4 bita di bawah awal buffer peta `map_base` (`ebp - 0xa98`).
  3. Memposisikan koordinat pada `row = 0` dan `col = -4` menyebabkan penulisan karakter pemain `@` (`0x40`) langsung menimpa `has_flag` menjadi bernilai `true`. Dipadukan dengan pintasan pengembang `'p'` yang memanggil `solve_round()`, fungsi `win()` dieksekusi secara sah.
- **Validasi Validator:** Submisi token `academy{gamer_m0d3_enabled_9ad09239}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 347 `chrono` (General Skills, Medium, picoCTF 2023)
- **Arsitektur & Batas Input:** Lingkungan kontainer Linux Debian on-demand dengan akses SSH pengguna `picoplayer`.
- **Akar Kerentanan (CWE-312 / CWE-200 / NIST SP 800-115 § 4.2):**
  1. Berkas penjadwalan sistem `/etc/crontab` memiliki hak akses POSIX bawaan `644` (`-rw-r--r--`), sehingga dapat dibaca oleh setiap proses lokal tanpa eskalasi privilese.
  2. Administrator meninggalkan token sensitif pada baris komentar header crontab tanpa proteksi isolasi rahasia.
- **Validasi Validator:** Submisi token `academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_207_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (576/576 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_344`: **PASS** (reproduksi eksploitasi injeksi argumen CDP exit 0, token cocok).
3. `solve_345`: **PASS** (reproduksi eksploitasi penulisan indeks negatif stack exit 0, token cocok).
4. `solve_347`: **PASS** (reproduksi enumerasi crontab sistem exit 0, token cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/picoCTF-2023/`, zero em dash).
