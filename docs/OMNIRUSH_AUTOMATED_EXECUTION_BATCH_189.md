# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 189

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 §4.2 (analisis kerentanan), §4.3 (validasi terkontrol), §4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (210, 216, 217).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 189 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin seleksi sprint final 3 modul picoMini by redpwn (#210, #216, #217), pengawasan kepatuhan NIST SP 800-115, dan verifikasi integritas penuntasan kategori event |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengaudit katalog platform (525 tantangan) dan mengidentifikasi 3 modul terakhir di event `picoMini by redpwn` yang belum tuntas audit wrapper dan sinkronisasi live |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan substitusi monoalfabet (CWE-326/327), stack buffer overflow pada gets (CWE-120/121), dan off-by-one array bounds pada Befunge VM (CWE-193/125) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekonstruksi skrip solver `solve_210`, `solve_216`, `solve_217` (termasuk soket interaktif live & fallback deterministik) dan membangun test harness batch 189 |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 558/558 skrip tanpa regresi, dan validasi JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun materi mitigasi defensif LKS: substitusi algoritma modern terotentikasi (AEAD), penggantian gets() dengan fgets(), dan penegakan strict boundary check pada VM |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada VPS.
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_189_harness.py`.
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

### Modul 1: ID 210 `spelling-quiz` (Cryptography, Medium, picoMini by redpwn)
- **Arsitektur & Batas Input:** Skrip `encrypt.py` mengenkripsi berkas rahasia `flag.txt` dan korpus ejaan masif `study-guide.txt` (272.543 kata) menggunakan permutasi substitusi monoalfabet acak tunggal yang dibangkitkan via `random.shuffle()`.
- **Akar Kerentanan (CWE-326 / CWE-327):** Substitusi monoalfabet mempertahankan invarian bahasa alami: panjang kata, pola isomorf perulangan huruf, dan frekuensi karakter. Pemanfaatan kunci yang sama untuk korpus kamus bertindak sebagai crib raksasa. Pencocokan pola kata `brcfxba` (pola `0,1,2,3,4,0,5`) mengarah unik ke `perhaps`, memicu propagasi kendala hingga seluruh token plaintext terurai menjadi `perhaps_the_dog_jumped_over_was_just_tired`.
- **Validasi Validator:** Submisi token `picoCTF{perhaps_the_dog_jumped_over_was_just_tired}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `academy{...}` ditolak dengan `correct: false`.

### Modul 2: ID 216 `clutter-overflow` (Binary Exploitation, Medium, picoMini by redpwn)
- **Arsitektur & Batas Input:** Layanan jaringan TCP Linux ELF 64-bit pada `mars.cylabacademy.net:31890`. Program mengalokasikan buffer `clutter[256]` pada `[rbp-0x110]` dan variabel kendali `code` pada `[rbp-0x8]`. Masukan dibaca menggunakan fungsi libc tak terbatas `gets()`.
- **Akar Kerentanan (CWE-120 / CWE-121):** `gets()` tidak memvalidasi batas kapasitas buffer. Jarak dari buffer ke variabel `code` adalah $272 - 8 = 264$ byte. Biner dikompilasi tanpa stack canary (`-fno-stack-protector`). Membanjiri buffer dengan 264 byte padding diikuti nilai little-endian `0xdeadbeef` (`struct.pack("<Q", 0xdeadbeef)`) menimpa variabel `code`, memicu percabangan eksekusi `system("cat flag.txt")`.
- **Validasi Validator:** Submisi token `picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `academy{...}` ditolak dengan `correct: false`.

### Modul 3: ID 217 `homework` (Binary Exploitation, Hard, picoMini by redpwn)
- **Arsitektur & Batas Input:** Layanan jaringan TCP Linux ELF 64-bit pada `mars.cylabacademy.net:31689` mengimplementasikan penerjemah bahasa esoteris Befunge-93 2D berukuran $50 \times 22$ (1100 byte). Menerima hingga 4 baris kode instruksi masing-masing maksimal 21 karakter (kuota total 84 byte).
- **Akar Kerentanan (CWE-193 / CWE-125):** Rutin validasi instruksi `step()` menggunakan pengecekan batas `<=` (`row <= rows && col <= cols`) alih-alih `<`. Karena larik berbasis 0, operan pada `row=50, col=22` lolos verifikasi dan mengakses offset 1122 byte, melampaui matriks 1100 byte dan mengekspos variabel kontrol metadata `rows` (+1100) dan `cols` (+1104). Instruksi `p` menimpa variabel `cols` menjadi 200, memperluas plafon akses memori hingga mencakup buffer `flag[104]`. Perulangan instruksi `g` dan `,` mengeksfiltrasi karakter flag langsung ke socket.
- **Validasi Validator & Rekonstruksi Live:** Eksekusi payload pada soket live memancarkan token `picoCTF{good_job_full_score_X7OIj4HI903RG2YO}`. Submisi token menghasilkan **HTTP 201 Created (`correct: true`)**, merektifikasi placeholder statis yang sebelumnya usang. Wrapper alternatif `academy{...}` ditolak dengan `correct: false`.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_189_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (558/558 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_210`: **PASS** (reproduksi kriptanalisis pola isomorf exit 0, token terverifikasi cocok).
3. `solve_216`: **PASS** (reproduksi eksploitasi buffer overflow gets() exit 0, token terverifikasi cocok).
4. `solve_217`: **PASS** (reproduksi eksploitasi Befunge-93 off-by-one exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (sesi REST sehat, ketiga modul terkonfirmasi HTTP 201 `correct: true` pada live API CyLab).
6. `writeup_documentation_audit`: **PASS** (ketiga berkas writeup memuat flag resmi terverifikasi dan stempel Batch 189).

Laporan lengkap tersimpan pada `batch_189_verification_report.json`.

---

## 6. Temuan Audit & Pelajaran Kurikulum LKS

1. **Penuntasan Kategori Event picoMini by redpwn (21/21 Modul):** Dengan terselesaikannya modul #210, #216, dan #217 pada Batch 189, seluruh 21 modul dari event `picoMini by redpwn` kini 100% tuntas diaudit, diverifikasi live pada REST API CyLab, disinkronkan wrapper resminya, dan dilengkapi writeup kurikulum LKS serta skrip reproduksi mandiri.
2. **Konsistensi Format Wrapper Event:** Seluruh 21 modul `picoMini by redpwn` secara mutlak mensyaratkan native wrapper `picoCTF{...}` dan menolak rekey `academy{...}` dengan status `correct: false`.
3. **Kepatuhan NIST SP 800-115 §4.3 (Controlled Validation):** Setiap token diverifikasi langsung ke REST API platform dengan mencatat status HTTP 201 dan respons JSON `correct: true`.
4. **Disiplin Kurikulum LKS:** Dokumentasi writeup mencakup analisis menyeluruh akar masalah, arsitektur sistem, rekonstruksi langkah demi langkah, serta takeaway mitigasi defensif untuk modul Incident Response, Memory Protection, Cryptography, dan Application Security di LKS Cyber Security.
