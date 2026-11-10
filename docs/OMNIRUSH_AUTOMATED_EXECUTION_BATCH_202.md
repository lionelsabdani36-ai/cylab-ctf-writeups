# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 202

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (270, 271, 272). Kelanjutan Event picoCTF 2022 (20/65 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 202 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 202, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian tuntas 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan event picoCTF 2022 (#270 Forbidden Paths, #271 Fresh Java, #272 function overwrite), memverifikasi endpoint web on-demand form read.php, artefak bytecode Java KeygenMe.class, dan biner ELF 32-bit vuln |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan filter blacklist parsial dan directory traversal (CWE-22 / OWASP A01), penyimpanan kredensial statis dan verifikasi per-karakter pada bytecode JVM (CWE-312 / CWE-798), serta signed array bounds check omission dan function pointer overwrite (CWE-129 / CWE-822) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekayasa dan memperbarui skrip solver otomatis mandiri `solve_270_forbidden_paths.py`, `solve_271_fresh_java.py`, dan `solve_272_function_overwrite.py`, serta membangun suite uji deterministik `test_batch_202_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 571/571 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform (HTTP 201 correct:true), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: kanonikalisasi path dan whitelisting pada modul Web Security, pemahaman stack-based architecture JVM pada Reverse Engineering, serta dual-bound integer validation dan proteksi Full RELRO / CFI pada Binary Exploitation |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada lingkungan VPS (`lionelsabdani36@gmail.com`).
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_202_harness.py`.
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

### Modul 1: ID 270 `Forbidden Paths` (Web Exploitation, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Aplikasi web pembaca berkas (eReader) interaktif menerima parameter `filename` via HTTP `POST /read.php`. Berkas web berada di `/var/www/html/` dan flag berada di `/flag.txt`.
- **Akar Kerentanan (CWE-22 / OWASP A01 / NIST SP 800-115 § 4.3):**
  1. Validasi filter hanya memeriksa apakah karakter pertama masukan diawali garis miring (`/`), menolak absolute path dengan pesan "Not Authorized".
  2. Filter gagal mengkanonikalisasi jalur atau memblokir traversal direktori relatif (`../`).
  3. Dokumen web berada di kedalaman 3 tingkat direktori dari root (`/var/www/html/`), sehingga muatan `../../../flag.txt` keluar ke root sistem berkas dan membaca `/flag.txt`.
- **Validasi Validator:** Submisi token `academy{7h3_p47h_70_5ucc355_afd5d939}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 271 `Fresh Java` (Reverse Engineering, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Berkas biner kelas Java terkompilasi `KeygenMe.class` (1,883 bytes, format class version 55.0 Java 11). Program memvalidasi masukan lisensi pengguna karakter per karakter.
- **Akar Kerentanan (CWE-312 / CWE-798 / NIST SP 800-115 § 4.3):**
  1. Ketiadaan obfuskasi bytecode JVM mempertahankan alur kontrol dan instruksi perbandingan terbuka.
  2. Validasi linear memanggil `invokevirtual String.charAt:(I)C` (opcode `0xb6`) diikuti pemuatan karakter ekspektasi via `bipush` (opcode `0x10 <ascii_val>`) dan percabangan `if_icmpne`.
  3. Pemindaian pola instruksi biner langsung memulihkan 34 karakter kunci lisensi dari indeks 0 hingga 33 secara deterministik tanpa JVM runtime.
- **Validasi Validator:** Submisi token `academy{700l1ng_r3qu1r3d_5e462060}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 272 `function overwrite` (Binary Exploitation, Hard, picoCTF 2022)
- **Arsitektur & Batas Input:** Biner ELF 32-bit x86 unstripped (`vuln`, no PIE, partial RELRO). Program mengalkulasi skor ASCII cerita pengguna ke dalam buffer 64 byte, lalu menerima dua bilangan bulat `num1` dan `num2` untuk memodifikasi array global `fun[10]`.
- **Akar Kerentanan (CWE-129 / CWE-822 / NIST SP 800-115 § 5.3):**
  1. Pemeriksaan `num1 < 10` hanya memvalidasi batas atas dan mengabaikan batas bawah (`num1 >= 0`) pada tipe data bertanda (`int`).
  2. Pointer fungsi global `check` (0x0804c034) dialokasikan di alamat sebelum array `fun` (0x0804c060) dengan jarak selisih 44 byte (indeks offset `num1 = -11`).
  3. Menambahkan selisih delta $\Delta = \text{easy\_checker} - \text{hard\_checker} = -310$ via `fun[-11] += (-310)` mengalihkan pointer fungsi ke `easy_checker`.
  4. String cerita `"~~~~~~~~~~M"` menghasilkan skor tepat 1337 ($10 \times 126 + 77 = 1337$), memicu pencetakan flag rahasia.
- **Validasi Validator:** Submisi token `academy{0v3rwrit1ng_P01nt3rs_2ba33ab3}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_202_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (571/571 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_270`: **PASS** (reproduksi live relative traversal & filter bypass exit 0, token cocok).
3. `solve_271`: **PASS** (reproduksi static JVM bytecode pattern scan exit 0, token cocok).
4. `solve_272`: **PASS** (reproduksi negative index array write & function pointer redirection exit 0, token cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/picoCTF-2022/`).
