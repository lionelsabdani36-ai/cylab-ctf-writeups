# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 196

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (251, 252, 253). Penuntasan Event Beginner picoMini 2022 (13/13 modul) & Inisiasi Event picoCTF 2022 (2/65 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 196 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 196, memastikan kepatuhan standar NIST SP 800-115, aturan anti-slop (zero em dash), serta integrasi repositori |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul penutup event Beginner picoMini 2022 (#251 Serpentine, 13/13 tuntas) serta menginisiasi audit event picoCTF 2022 (#252 basic-file-exploit, #253 basic-mod1) |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan alur kendali mati dan hardcoded credential (CWE-670 / CWE-798), ambiguitas nilai kembali sentinel fungsi strtol POSIX C (CWE-20 / CWE-704), serta substitusi monoalfabetik unkeyed modulo 37 (CWE-327) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Mengembangkan dan menyempurnakan skrip solver mandiri `solve_251`, `solve_252`, `solve_253` dengan fallback deterministik offline dan live socket/HTTP support, serta menyusun suite uji test harness `test_batch_196_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 565/565 skrip Python tanpa regresi sintaks, evaluasi matriks wrapper platform (academy vs picoCTF), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: analisis aliran kendali Python (control flow analysis), pemeriksaan batas tipe data dan konversi string pada kode biner C, serta pemahaman matematika modular diskret |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang dan siap digunakan pada VPS.
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_196_harness.py`.
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

### Modul 1: ID 251 `Serpentine` (General Skills, Easy, Beginner picoMini 2022)
- **Arsitektur & Batas Input:** Skrip interaktif Python `serpentine.py` berbasis menu perulangan konsol (`a`, `b`, `c`).
- **Akar Kerentanan (CWE-670 / CWE-798 / CWE-327 / NIST SP 800-115 § 4.2):**
  1. Kredensial bendera disematkan langsung di sisi klien dalam bentuk array biner `flag_enc` dan kunci statis `"enkidu"`.
  2. Fungsi `print_flag()` telah didefinisikan lengkap di baris atas skrip, namun pada percabangan menu `elif choice == 'b':`, program menampilkan pesan pengalih perhatian dan sengaja tidak memanggil `print_flag()`.
  3. Memanggil langsung fungsi `str_xor(flag_enc, 'enkidu')` secara offline memulihkan token teks terang secara instan.
- **Validasi Validator:** Submisi token `academy{7h3_r04d_l355_7r4v3l3d_825b10ae}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper `picoCTF{...}` menghasilkan `correct: false`.

### Modul 2: ID 252 `basic-file-exploit` (Binary Exploitation, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Layanan TCP dan kode sumber C `program-redacted.c` yang mengimplementasikan sistem penyimpanan basis data memori sederhana (tulis data, baca data per nomor entri).
- **Akar Kerentanan (CWE-20 / CWE-704 / CWE-670 / NIST SP 800-115 § 4.2):**
  1. Pada fungsi `data_read()`, input nomor entri diparsing menggunakan `strtol(entry, NULL, 10)`.
  2. Berdasarkan standar POSIX ISO C, `strtol` mengembalikan nilai integer `0` baik saat input berupa karakter `"0"` maupun saat konversi gagal karena string non-numerik (seperti `"abc"`).
  3. Percabangan validasi `if ((entry_number = strtol(entry, NULL, 10)) == 0)` mengeksekusi `puts(flag)` dan keluar dari program.
  4. Penyerang yang memasukkan setidaknya satu frasa pada menu 1 (`inputs > 0`) lalu memilih menu 2 dengan memasukkan string `"abc"` atau `"0"` memicu pencetakan flag tanpa batasan hak akses.
- **Validasi Validator:** Submisi token `academy{M4K3_5UR3_70_CH3CK_Y0UR_1NPU75_6A9F6821}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper `picoCTF{...}` menghasilkan `correct: false`.

### Modul 3: ID 253 `basic-mod1` (Cryptography, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Berkas artefak `message.txt` memuat 22 token bilangan bulat yang dipisahkan spasi.
- **Akar Kerentanan (CWE-327 / NIST SP 800-115 § 4.2):**
  1. Skema enkripsi merupakan substitusi monoalfabetik unkeyed berbasis ring modular $\mathbb{Z}_{37}$.
  2. Tiap bilangan direduksi modulo 37 dan dipetakan langsung ke tabel karakter 37 simbol (0-25 untuk A-Z, 26-35 untuk 0-9, 36 untuk `_`).
  3. Ketiadaan kunci rahasia (*unkeyed*), ketiadaan difusi (*no block dependency*), dan determinisme modulo membuat dekripsi trivial untuk dibalik.
- **Validasi Validator:** Submisi token `academy{R0UND_N_R0UND_65371195}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper `picoCTF{...}` menghasilkan `correct: false`.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_196_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (565/565 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_251`: **PASS** (dekripsi stream XOR statis serpentine exit 0, token terverifikasi cocok).
3. `solve_252`: **PASS** (simulasi parsing POSIX strtol & logika bypass exit 0, token terverifikasi cocok).
4. `solve_253`: **PASS** (evaluasi kelas kongruensi modulo 37 pada 22 token exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/Beginner-picoMini-2022/` dan `writeups/picoCTF-2022/`).
