# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 209

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (350, 351, 352). Kelanjutan Audit Event picoCTF 2023 (9/42 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 209 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 209, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian sekuensial 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan event picoCTF 2023 (#350 hideme, #351 HideToSee, #352 hijacking), menganalisis struktur format berkas PNG IEND trailer, ekstraksi koefisien frekuensi DCT JPEG, dan audit hierarki direktori berizin tulis Linux |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan file carving trailing data PKZIP polyglot (CWE-434 / CWE-200), kelemahan sandi substitusi monoalfabetik klasik Atbash (CWE-327 / CWE-319), serta diskrepansi izin sudoers NOPASSWD dan pembajakan impor pustaka Python sys.path[0] (CWE-250 / CWE-732 / CWE-427) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekayasa dan memperbarui skrip solver otomatis mandiri `solve_350_hideme.py`, `solve_351_hidetosee.py`, dan `solve_352_hijacking.py`, serta membangun suite uji deterministik `test_batch_209_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 578/578 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform (HTTP 201 correct:true), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: rekayasa berkas polyglot & Content Disarm and Reconstruction (CDR), pemahaman kriptografi klasik vs modern, serta pengerasan konfigurasi sudoers terisolasi (flag -I) |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada lingkungan VPS (`lionelsabdani36@gmail.com`).
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_209_harness.py`.
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

### Modul 1: ID 350 `hideme` (Forensics, Medium, picoCTF 2023)
- **Arsitektur & Batas Input:** Analisis artefak grafis format PNG (`flag.png`) berukuran 21.768 byte.
- **Akar Kerentanan (CWE-434 / CWE-200 / ISO/IEC 15948 / NIST SP 800-115 § 4.2):**
  1. Spesifikasi kontainer PNG mengakhiri aliran data pada chunk `IEND` (`\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82`). Aplikasi peramban dan penampil grafis standar mengabaikan byte data tambahan setelah penanda ini.
  2. Pada offset biner 15.929 (`0x3E39`), ditemukan signature lokal berkas arsip PKZIP (`PK\x03\x04`). Arsip ini menyematkan direktori `secret/` yang memuat berkas gambar `secret/flag.png` berukuran 5.517 byte.
  3. Pemotongan byte (*file carving*) dan pembacaan teks via Optical Character Recognition (OCR) memulihkan token bendera secara instan.
- **Validasi Validator:** Submisi token live `academy{Hiddinng_An_imag3_within_@n_ima9e_404ff71e}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 351 `HideToSee` (Cryptography, Medium, picoCTF 2023)
- **Arsitektur & Batas Input:** Analisis artefak grafis JPEG (`atbash.jpg`) berukuran 51.503 byte.
- **Akar Kerentanan (CWE-327 / CWE-319 / NIST SP 800-115 § 4.2):**
  1. Steganografi domain frekuensi DCT JPEG diekstraksi menggunakan utilitas `steghide` dengan frasa sandi kosong (`""`), memulihkan teks tersandi `zxzwvnb{zgyzhs_xizxp_6167yw8v}`.
  2. Nama berkas `atbash.jpg` secara langsung merujuk pada sandi substitusi klasik Atbash ($c \equiv (25 - p) \pmod{26}$).
  3. Pembalikan pemetaan alfabetik deterministik mendekripsi teks tersandi menjadi `academy{atbash_crack_6167bd8e}` tanpa modifikasi karakter numerik.
- **Validasi Validator:** Submisi token live `academy{atbash_crack_6167bd8e}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 352 `hijacking` (Binary Exploitation, Medium, picoCTF 2023)
- **Arsitektur & Batas Input:** Lingkungan Linux interaktif via SSH dengan akun tak berizin istimewa `academy`.
- **Akar Kerentanan (CWE-250 / CWE-732 / CWE-427 / PEP 273 / NIST SP 800-115 § 4.2):**
  1. Konfigurasi `sudo -l` mengizinkan eksekusi tanpa kata sandi: `(root) NOPASSWD: /usr/bin/python3 /home/academy/.server.py`.
  2. Skrip `.server.py` berstatus read-only milik root, namun direktori induk `/home/academy/` dimiliki dan dapat ditulisi penuh oleh user `academy` (`drwxr-x---`).
  3. Semantik runtime CPython secara otomatis menyisipkan direktori skrip target ke posisi pertama resolusi modul (`sys.path[0]`).
  4. Skrip mengimpor modul pustaka standar `base64`, `os`, dan `socket`. Pembuatan berkas palsu `/home/academy/base64.py` membajak proses impor saat dieksekusi via `sudo`, mengeksekusi payload arbiter dengan UID 0 (root) untuk membaca `/root/flag.txt`.
- **Validasi Validator:** Submisi token live `academy{pYth0nn_libraryH!j@CK!n9_15d0fa80}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_209_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (578/578 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_350`: **PASS** (reproduksi PNG file carving PKZIP exit 0, token cocok).
3. `solve_351`: **PASS** (reproduksi steghide extract & Atbash decryption exit 0, token cocok).
4. `solve_352`: **PASS** (reproduksi Python module hijacking sudo escalation exit 0, token cocok).
5. `live_evidence_probes`: **PASS** (katalog CyLab HTTP 200, penyerahan token modul 350, 351, 352 terverifikasi HTTP 201 Created `correct: true`).
6. `writeup_documentation_audit`: **PASS** (writeup memuat 5 bab LKS wajib, token resmi tervalidasi, kepatuhan anti-slop zero em dash terverifikasi 100%).

Laporan artefak JSON tersimpan pada `batch_209_verification_report.json`.
