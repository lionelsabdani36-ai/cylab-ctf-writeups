# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 188

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 §4.2 (analisis kerentanan), §4.3 (validasi terkontrol), §4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (202, 205, 208).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 188 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin seleksi sprint 3 modul picoMini by redpwn, pengawasan kepatuhan NIST SP 800-115, dan verifikasi integritas end-to-end |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul target yang memerlukan audit wrapper dan standardisasi writeup di kategori event `picoMini by redpwn` |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan Command Injection (CWE-78), Corrupted PNG File Signature (CWE-1288), dan State Space Reduction Multilayer XOR (CWE-327) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekonstruksi skrip solver `solve_202`, `solve_205`, `solve_208` ke format wrapper native terverifikasi dan membangun test harness batch 188 |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi live `POST /api/submissions/` dengan CSRF token, sweep AST 557/557 skrip, dan validasi JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun materi mitigasi defensif LKS: parameterized command execution, validasi strict magic bytes, dan penggunaan kriptografi standar modern |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada VPS.
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_188_harness.py`.
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

### Modul 1: ID 202 `caas` (Web Exploitation, Medium, picoMini by redpwn)
- **Arsitektur & Batas Input:** Layanan web Node.js Express mengekspos endpoint `GET /cowsay/:message`, meneruskan parameter pengguna langsung ke `child_process.exec('/usr/games/cowsay ' + message)`. Direktori kerja `/app` berisi berkas target `falg.txt`.
- **Akar Kerentanan (CWE-78):** Interpolasi string langsung ke dalam `child_process.exec()` memanggil shell sistem `/bin/sh -c` tanpa sanitasi metakarakter. Penggunaan delimiter titik koma URL-encoded `%3B` memutus perintah `cowsay` dan mengeksekusi `cat falg.txt` sebagai user `node`.
- **Validasi Validator:** Submisi token `picoCTF{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `academy{...}` ditolak dengan `correct: false`.

### Modul 2: ID 205 `advanced-potion-making` (Forensics, Medium, picoMini by redpwn)
- **Arsitektur & Batas Input:** Berkas biner grafis tanpa ekstensi dengan header rusak. Tanda tangan awal 8-byte PNG dirusak pada offset 2..3 (`89 50 42 11` alih-alih `89 50 4E 47`) dan panjang chunk data IHDR dirusak menjadi `00 12 13 14` alih-alih `00 00 00 0D`.
- **Akar Kerentanan (CWE-1288):** Ketidakkonsistenan biner pada magic bytes dan chunk metadata (RFC 2083). Data chunk IHDR tetap utuh dan cocok dengan checksum CRC-32 `0x042DE778` (dimensi 2448x1240 Truecolor RGB). Citra yang diperbaiki menampilkan kanvas merah pekat, di mana glif teks bendera disembunyikan menggunakan variasi saluran warna merah.
- **Validasi Validator:** Submisi token `picoCTF{w1z4rdry}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `academy{...}` ditolak dengan `correct: false`.

### Modul 3: ID 208 `XtraORdinary` (Cryptography, Medium, picoMini by redpwn)
- **Arsitektur & Batas Input:** Skrip Python `encrypt.py` menerapkan perulangan bersarang acak berulang menggunakan string dari array `random_strs` setelah melakukan enkripsi repeating-key XOR pada flag. Berkas ciphertext heksadesimal berukuran 39 byte disediakan pada `output.txt`.
- **Akar Kerentanan (CWE-327):** Operasi bitwise XOR bersifat komutatif, asosiatif, dan merupakan sebuah involusi ($A \oplus B \oplus B = A$). Jumlah penerapan genap saling membatalkan ($0$) dan ganjil setara satu kali ($1$). Dari daftar string, hanya ada 5 string unik, mereduksi ruang keadaan dari ribuan perulangan menjadi hanya $2^5 = 32$ kemungkinan mask efektif. Serangan Known-Plaintext Attack pada prefiks `picoCTF{` mengungkap kunci berulang `Africa!`.
- **Validasi Validator:** Submisi token `picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `academy{...}` ditolak dengan `correct: false`.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_188_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (557/557 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_202`: **PASS** (reproduksi eksploitasi injeksi perintah exit 0, token terverifikasi cocok).
3. `solve_205`: **PASS** (reproduksi perbaikan header PNG biner exit 0, token terverifikasi cocok).
4. `solve_208`: **PASS** (reproduksi dekripsi 32-state XOR exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (sesi REST sehat, ketiga modul terkonfirmasi HTTP 201 `correct: true` pada live API CyLab).
6. `writeup_documentation_audit`: **PASS** (ketiga berkas writeup memuat flag resmi terverifikasi dan stempel Batch 188).

Laporan lengkap tersimpan pada `batch_188_verification_report.json`.

---

## 6. Temuan Audit & Pelajaran Kurikulum LKS

1. **Konsistensi Format Wrapper Event:** Modul #202, #205, dan #208 kembali menegaskan pola platform bahwa seluruh modul backport event `picoMini by redpwn` secara konsisten mensyaratkan native wrapper `picoCTF{...}` dan menolak rekey `academy{...}` dengan status `correct: false`.
2. **Kepatuhan NIST SP 800-115 §4.3 (Controlled Validation):** Setiap token diverifikasi langsung ke REST API platform dengan mencatat status HTTP 201 dan respons JSON `correct: true`.
3. **Disiplin Kurikulum LKS:** Dokumentasi writeup mencakup analisis menyeluruh akar masalah, arsitektur sistem, rekonstruksi langkah demi langkah, serta takeaway mitigasi defensif untuk modul Incident Response, Web Security, Forensics, dan Cryptography di LKS Cyber Security.
