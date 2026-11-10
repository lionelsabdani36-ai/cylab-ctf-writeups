# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 187

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 §4.2 (analisis kerentanan), §4.3 (validasi terkontrol), §4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (211, 221, 222).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 187 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin seleksi sprint 3 modul picoMini by redpwn, pengawasan kepatuhan NIST SP 800-115, dan verifikasi integritas end-to-end |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul target yang memerlukan audit wrapper dan rektifikasi token kriptografi di kategori event `picoMini by redpwn` |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis matematis Coppersmith small-roots LLL reduction pada RSA 1024-bit, dekompilasi ISA bytecode stack VM maze, dan ekstraksi plaintext memcmp |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekonstruksi skrip solver `solve_211`, `solve_221`, `solve_222` ke format wrapper native terverifikasi dan membangun test harness batch 187 |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi live `POST /api/submissions/` dengan CSRF token, sweep AST 556/556 skrip, dan validasi JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun materi mitigasi defensif LKS: proteksi integritas kunci privat asimetris, pengerasan bytecode VM, dan zeroization plaintext memori |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 mengembalikan pesan operasional:
  `omnirush: OmniRush is under maintenance until further notice.`
- **Integritas Pelaporan:** Kondisi pemeliharaan upstream dilaporkan apa adanya tanpa fabrikasi output.
- **Eksekusi Pengganti:** Orkestrasi coding agent dijalankan melalui toolchain internal Hermes dan harness deterministik Python `scripts/test_batch_187_harness.py`.

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

### Modul 1: ID 211 `corrupt-key-2` (Cryptography, Hard, picoMini by redpwn)
- **Arsitektur & Batas Input:** Kunci privat RSA 1024-bit ASN.1 DER (`private.pem`) dengan modulus composite $N$, eksponen publik $e = 65537$, dan faktor prima $p$ yang mengalami korupsi parsial pada 3 segmen non-contiguous: 40 bit pada offset 16 ($X_0 = 2^{40}$), 32 bit pada offset 240 ($X_1 = 2^{32}$), dan 40 bit pada offset 352 ($X_2 = 2^{40}$). Total bit tak diketahui = 112 bit.
- **Akar Kerentanan (CWE-326, CWE-327):** Batas Coppersmith menetapkan $X < N^{0.25} = 2^{256}$. Ruang pencarian $2^{112}$ berada jauh di bawah ambang batas teoretis. Persamaan pergeseran Howgrave-Graham multivariat $f(x_0, x_1, x_2) = \tilde{p} + 2^{16}x_0 + 2^{240}x_1 + 2^{352}x_2 \equiv 0 \pmod p$ direduksi via kisi LLL, memulihkan faktor prima $p$ secara eksak. Eksponen privat $d \equiv e^{-1} \pmod{\phi(N)}$ mendekripsi berkas `msg_2.enc`.
- **Validasi Validator:** Submisi token `picoCTF{1d68da1447328c3f11541d076c9c613957d86566}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `academy{...}` ditolak dengan `correct: false`.

### Modul 2: ID 221 `MATRIX` (Reverse Engineering, Hard, picoMini by redpwn)
- **Arsitektur & Batas Input:** Biner Linux x86-64 ELF stripped dengan Partial RELRO, Canary, NX, No PIE. Biner mengeksekusi mesin virtual (VM) stack-based internal yang membaca sekuens input arah `u`, `d`, `l`, `r` untuk menavigasi labirin virtual di memori.
- **Akar Kerentanan (CWE-829, CWE-670):** VM mengimplementasikan pos pemeriksaan HP (tile `^` menambah HP, tile `!` mensyaratkan HP $\ge 5$, tile `$` adalah pintu keluar pemicu loop cetak flag). Pencarian ruang keadaan BFS membuktikan jalur terpendek geometris gagal karena kekurangan HP. Sekuens pergerakan osilasi bolak-balik awal sepanjang 63 langkah (`rrrrrlrlrlrlrllddddddlddrrddrrrdrddrruuuruuuuuuurrddddddddlddrd`) mengumpulkan cadangan HP yang cukup untuk menembus seluruh 5 checkpoint.
- **Validasi Validator:** Submisi token `picoCTF{y0uv3_3sc4p3d_th3_m4ze...f0r_n0w-hYkq2D9PmrA5GpEq}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `academy{...}` ditolak dengan `correct: false`.

### Modul 3: ID 222 `not crypto` (Reverse Engineering, Hard, picoMini by redpwn)
- **Arsitektur & Batas Input:** Biner Linux x86-64 ELF dengan Full RELRO, Canary, NX, dan PIE. Program meminta masukan persis 64 byte, menerapkan enkripsi AES, dan memeriksa hasil enkripsi terhadap buffer target menggunakan fungsi pustaka C `memcmp()`.
- **Akar Kerentanan (CWE-208, CWE-311):** Biner tidak memiliki proteksi anti-debugging (`ptrace` / timing traps). Sebelum pemanggilan `memcmp()`, program mendekripsi string flag target ke buffer memori sementara yang ditunjuk oleh register pertama `RDI`. Pemasangan breakpoint dinamis pada fungsi `memcmp` di GDB mengekspos teks polos bendera secara instan tanpa perlu memecahkan matematika kriptografi.
- **Validasi Validator:** Submisi token `picoCTF{c0mp1l3r_0pt1m1z4t10n_15_pur3_w1z4rdry_but_n0_pr0bl3m?}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `academy{...}` ditolak dengan `correct: false`.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_187_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (556/556 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_211`: **PASS** (reproduksi deterministik exit 0, token terverifikasi cocok).
3. `solve_221`: **PASS** (reproduksi sekuens navigasi VM exit 0, token terverifikasi cocok).
4. `solve_222`: **PASS** (reproduksi analisis dinamis in-memory exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (sesi REST sehat, ketiga modul terkonfirmasi HTTP 201 `correct: true` pada live API CyLab).
6. `writeup_documentation_audit`: **PASS** (ketiga berkas writeup memuat flag resmi terverifikasi dan stempel Batch 187).

Laporan lengkap tersimpan pada `batch_187_verification_report.json`.

---

## 6. Temuan Audit & Pelajaran Kurikulum LKS

1. **Rektifikasi Token Matematis & Integritas Kripto:** Pada modul #211, audit membuktikan bahwa pemecahan Coppersmith LLL terhadap berkas asli `msg_2.enc` menghasilkan token definitif `picoCTF{1d68da1447328c3f11541d076c9c613957d86566}`, yang diterima live validator platform dengan HTTP 201 `correct: true`.
2. **Konsistensi Format Wrapper Event:** Modul #211, #221, dan #222 mengonfirmasi bahwa seluruh modul backport event `picoMini by redpwn` secara konsisten mensyaratkan native wrapper `picoCTF{...}` dan menolak rekey `academy{...}`.
3. **Kepatuhan NIST SP 800-115 §4.3 (Controlled Validation):** Verifikasi submisi live mencatat status HTTP 201 `correct: true` langsung dari validator API platform.
4. **Disiplin Kurikulum LKS:** Dokumentasi writeup mencakup analisis menyeluruh akar masalah, arsitektur sistem, rekonstruksi langkah demi langkah, serta takeaway mitigasi defensif untuk modul Incident Response dan Hardening di LKS Cyber Security.
