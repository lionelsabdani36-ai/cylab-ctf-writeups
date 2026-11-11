# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 210

Tanggal: 11 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (353, 354, 355). Kelanjutan Audit Event picoCTF 2023 (12/42 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 210 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 210, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian sekuensial 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan event picoCTF 2023 (#353 Horsetrack, #354 Invisible WORDs, #355 Java Code Analysis!?!), menganalisis dinamika alokator heap Glibc 2.33 Safe-Linking, struktur interleaving 16-bit WORD berkas BMP, dan pola arsitektur token Spring Security JWT |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan Use-After-Free heap & tcache poisoning (CWE-416 / CWE-822 / CWE-78), steganografi interleaving saluran warna BMP (CWE-200 / CWE-532), serta pembangkitan kunci rahasia statis HMAC JWT dan eskalasi privilese vertikal RBAC (CWE-321 / CWE-798 / CWE-285) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekayasa dan memperbarui skrip solver otomatis mandiri `solve_353_horsetrack.py`, `solve_354_invisible_words.py`, dan `solve_355_java_code_analysis.py`, serta membangun suite uji deterministik `test_batch_210_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 579/579 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform (HTTP 201 correct:true), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: mitigasi UAF dengan pointer nullification dan Full RELRO/PIE, deteksi saluran tersembunyi via analisis entropi kanal warna, serta manajemen rahasia kriptografis terisolasi pada aplikasi berbasis enterprise Java |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada lingkungan VPS (`lionelsabdani36@gmail.com`).
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_210_harness.py`.
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

### Modul 1: ID 353 `Horsetrack` (Binary Exploitation, Hard, picoCTF 2023)
- **Arsitektur & Batas Input:** Biner Linux ELF 64-bit x86-64 dengan proteksi Partial RELRO, Canary found, NX enabled, No PIE (`0x400000`). Lingkungan GNU C Library versi 2.33 (`glibc 2.33`) dengan mekanisme proteksi pointer mangling *Safe-Linking* aktif pada tcache.
- **Akar Kerentanan (CWE-416 / CWE-822 / CWE-78 / NIST SP 800-115 § 4.2):**
  1. `remove_horse(idx)` memanggil `free(horses[idx].name)` dan menandai `in_use = 0`, namun tidak menghapus pointer menggantung (*dangling pointer*).
  2. Fungsi tersembunyi menu 0 (*cheat*) mengizinkan penulisan hingga 16 byte ke dalam `horses[idx].name` tanpa validasi status `in_use`.
  3. Safe-linking mengenkripsi pointer maju tcache melalui $P' = (L \gg 12) \oplus P$. Pada chunk pertama tcache, $P = 0$ sehingga nilai yang tersimpan membocorkan kunci halaman heap $(L \gg 12)$.
  4. Penyerang memalsukan pointer fd tcache dengan formula `heap_key ^ 0x404010`, mengarahkan alokasi ke tabel GOT `free@GOT` (`0x404018`), menimpanya dengan alamat `system@plt` (`0x401090`), dan memanggil `free(horse->name)` dengan muatan `"cat flag.txt\x00"` untuk membaca flag.
- **Validasi Validator:** Submisi token live `academy{t_cache_4ll_th3_w4y_2_th4_b4nk_744fb97a}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 354 `Invisible WORDs` (Forensics, Hard, picoCTF 2023)
- **Arsitektur & Batas Input:** Analisis artefak gambar bitmap Windows BMP 32-bit (`output.bmp`), resolusi 960x540 piksel (2.073.738 byte).
- **Akar Kerentanan (CWE-200 / CWE-532 / NIST SP 800-115 § 4.2):**
  1. Pada format BMP 32-bit, setiap piksel disimpan dalam urutan 4 byte BGRA: Blue (byte 0), Green (byte 1), Red (byte 2), Alpha (byte 3).
  2. Steganografi interleaving menyisipkan muatan biner pada pasangan 2-byte WORD rendah (saluran Blue dan Green) mulai dari offset biner `0x8c`, sementara 2-byte WORD tinggi (saluran Red dan Alpha) mempertahankan gradasi cover image.
  3. Ekstraksi byte secara interleaving merekonstruksi kontainer PKZIP (`PK\x03\x04`). Penelusuran record End of Central Directory (`PK\x05\x06`) memotong sisa padding piksel gambar.
  4. Dekompresi arsip ZIP memulihkan teks novel Frankenstein (`ZnJhbmtlbnN0ZWluLXRlc3QudHh0`) yang menyembunyikan token resmi kompetisi.
- **Validasi Validator:** Submisi token live `academy{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_75527d56}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 355 `Java Code Analysis!?!` (Web Exploitation, Medium, picoCTF 2023)
- **Arsitektur & Batas Input:** Aplikasi web enterprise Java Spring Boot BookShelf Pico dengan Role-Based Access Control (RBAC: Free, Premium, Admin). Dokumen buku rahasia flag (ID 5) hanya dapat diunduh oleh peran Admin.
- **Akar Kerentanan (CWE-321 / CWE-798 / CWE-285 / NIST SP 800-115 § 4.2):**
  1. Kelas `SecretGenerator.java` mengembalikan kunci statis fallback `"1234"` saat berkas rahasia server absen. Kunci ini digunakan untuk verifikasi dan pembuatan JWT HMAC-SHA256 (`HS256`).
  2. Endpoint `PATCH /base/users/role` menerapkan proteksi `@PreAuthorize("hasAuthority('Admin') and #userRoleRequest.id != ...")`. Penyerang memalsukan token JWT Admin dengan `userId: 9999` menggunakan secret `"1234"` untuk mempromosikan akun biasa (`userId: 1`) ke peran `Admin`.
  3. Akun yang telah dipromosikan mengunduh berkas PDF buku ID 5 via `GET /base/books/pdf/5`. Ekstraksi teks dari PDF mengungkap token resmi kompetisi.
- **Validasi Validator:** Submisi token live `academy{w34k_jwt_n0t_g00d_d3a1bea8}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_210_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (579/579 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_353`: **PASS** (reproduksi Glibc safe-linking UAF tcache poisoning exit 0, token cocok).
3. `solve_354`: **PASS** (reproduksi BMP 16-bit WORD interleaving ZIP carving exit 0, token cocok).
4. `solve_355`: **PASS** (reproduksi JWT HS256 secret forgery & RBAC privilege escalation exit 0, token cocok).
5. `live_evidence_probes`: **PASS** (katalog CyLab HTTP 200, penyerahan token modul 353, 354, 355 terverifikasi HTTP 201 Created `correct: true`).
6. `writeup_documentation_audit`: **PASS** (writeup memuat 5 bab LKS wajib, token resmi tervalidasi, kepatuhan anti-slop zero em dash terverifikasi 100%).

Laporan artefak JSON tersimpan pada `batch_210_verification_report.json`.
