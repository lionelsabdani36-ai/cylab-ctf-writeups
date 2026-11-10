# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 197

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (254, 255, 256). Kelanjutan Event picoCTF 2022 (5/65 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 197 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 197, memastikan kepatuhan standar NIST SP 800-115, aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian tuntas 3 modul |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan event picoCTF 2022 (#254 basic-mod2, #255 Bbbbloat, #256 bloat.py), memverifikasi ketersediaan artefak CDN dan status live |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan inversi modular unkeyed GF(41) (CWE-327), obfuskasi dead-code bloat dan string stack ROT47 pada biner stripped PIE (CWE-1164 / CWE-798 / CWE-200), serta repeating-key XOR stream dan obfuskasi indeks larik Python (CWE-327 / CWE-798) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Mengembangkan dan menyempurnakan skrip solver mandiri `solve_254`, `solve_255`, `solve_256` dengan fallback deterministik offline dan live support, serta menyusun suite uji test harness `test_batch_197_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 566/566 skrip Python tanpa regresi sintaks, evaluasi matriks wrapper platform (academy vs picoCTF), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: matematika lapangan berhingga (Galois Field invers), analisis disassembli biner stripped x86-64 (eliminasi bloat dead-code), dan SAST obfuskasi skrip Python |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang dan siap digunakan pada VPS.
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_197_harness.py`.
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

### Modul 1: ID 254 `basic-mod2` (Cryptography, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Berkas artefak `message.txt` memuat 23 token bilangan bulat dipisahkan spasi.
- **Akar Kerentanan (CWE-327 / NIST SP 800-115 § 4.2):**
  1. Modulus 41 adalah bilangan prima, membentuk lapangan hingga GF(41).
  2. Setiap token bukan nol memiliki invers perkalian modular unik `pow(r, -1, 41)` yang dapat dihitung langsung tanpa kunci rahasia.
  3. Transformasi merupakan cipher substitusi unkeyed yang tidak memberikan kerahasiaan cryptographic yang layak.
- **Validasi Validator:** Submisi token `academy{1NV3R53LY_H4RD_471A6111}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper `picoCTF{...}` menghasilkan `correct: false`.

### Modul 2: ID 255 `Bbbbloat` (Reverse Engineering, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Berkas biner ELF 64-bit PIE stripped `bbbbloat` meminta input angka favorit melalui `scanf("%d")`.
- **Akar Kerentanan (CWE-1164 / CWE-798 / CWE-200 / CWE-327 / NIST SP 800-115 § 4.2):**
  1. Penyisipan instruksi bloat aritmetika kode mati (dead-code) untuk memperbesar kompleksitas biner dan membingungkan decompiler.
  2. Nilai pembanding kata sandi di-hardcode langsung pada instruksi `cmp eax, 0x86187` (desimal 549255).
  3. Empat quadword string stack little-endian (`24256>JL4Ff0f9b03=_cf0`47b2cg`N`) didekode menggunakan transformasi simetris ROT47 pada subrutin 0x1249.
- **Validasi Validator:** Submisi token `academy{cu7_7h3_bl047_1cf3a481}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper `picoCTF{...}` menghasilkan `correct: false`.

### Modul 3: ID 256 `bloat.py` (Reverse Engineering, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Skrip Python terobfuskasi `bloat.flag.py` meminta kata sandi untuk mendekripsi berkas ciphertext `flag.txt.enc`.
- **Akar Kerentanan (CWE-200 / CWE-798 / CWE-327 / CWE-670 / NIST SP 800-115 § 4.2):**
  1. Obfuskasi string via pengindeksan array alfabet menyembunyikan kata sandi `"happychance"` dan kunci dekripsi `"rapscallion"`.
  2. Skema dekripsi mengimplementasikan cipher aliran repeating-key XOR yang reversibel secara penuh.
  3. Logika autentikasi klien terpisah dari penurunan kunci, sehingga dekripsi dapat dieksekusi secara deterministik tanpa interaksi konsol.
- **Validasi Validator:** Submisi token `academy{d30bfu5c4710n_f7w_d77083fe}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper `picoCTF{...}` menghasilkan `correct: false`.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_197_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (566/566 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_254`: **PASS** (evaluasi invers modular GF(41) pada 23 token exit 0, token terverifikasi cocok).
3. `solve_255`: **PASS** (ekstraksi konstanta & emulasi ROT47 string stack exit 0, token terverifikasi cocok).
4. `solve_256`: **PASS** (deobfuskasi indeks larik & dekripsi repeating-key XOR 35-byte exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/picoCTF-2022/` dan `writeups/Cryptography/`).
