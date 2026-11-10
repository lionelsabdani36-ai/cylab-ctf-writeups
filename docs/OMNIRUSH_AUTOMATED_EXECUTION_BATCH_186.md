# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 186

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 §4.2 (analisis kerentanan), §4.3 (validasi terkontrol), §4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (204, 219, 220).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 186 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin seleksi sprint 3 modul picoMini by redpwn, pengawasan kepatuhan NIST SP 800-115, dan verifikasi integritas end-to-end |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi kerentanan format wrapper drift pada kelas modul event `picoMini by redpwn` dari backlog writeup |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis traversal normalisasi Werkzeug url_fix, SSTI Jinja2 underscore bypass, RISC-V RV64 prefix invariance oracle, dan binary patch diffing |
| Alex (fullstack-dev) | Solver Remediation & Harness | Memperbarui skrip solver `solve_204`, `solve_219`, `solve_220` ke format wrapper native terverifikasi dan membangun test harness batch 186 |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi live `POST /api/submissions/` dengan CSRF token, sweep AST 555/555 skrip, dan validasi JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun materi mitigasi defensif LKS: penanganan jalur berkas kanonikal, strict avalanche criterion pada scrambler, dan patch verification reproducibility |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 mengembalikan pesan operasional:
  `omnirush: OmniRush is under maintenance until further notice.`
- **Integritas Pelaporan:** Kondisi pemeliharaan upstream dilaporkan apa adanya tanpa fabrikasi output.
- **Eksekusi Pengganti:** Orkestrasi coding agent dijalankan melalui toolchain internal Hermes dan harness deterministik Python `scripts/test_batch_186_harness.py`.

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

### Modul 1: ID 204 `notepad` (Web Exploitation, Hard, picoMini by redpwn)
- **Arsitektur & Batas Input:** Aplikasi web Flask dengan mesin templat Jinja2. Note disimpan ke `static/` menggunakan `werkzeug.utils.url_fix(content[:128])`. Filter masukan memblokir karakter `/` dan `_`. Halaman indeks merender templat via `{% include "errors/" + error + ".html" ignore missing %}`.
- **Akar Kerentanan (CWE-22, CWE-73, CWE-1336):** Fungsi `url_fix` mengonversi backslash `\` menjadi forward slash `/`. Masukan berawalan `..\templates\errors\` lolos filter `/`, namun dinormalisasi menjadi `../templates/errors/`, menempatkan catatan langsung di direktori templat. Filter `_` dibypass melalui refleksi argumen GET `request.args.get('c')`. Subclass `subprocess.Popen` (indeks 273) dieksekusi untuk membaca token bendera.
- **Validasi Validator:** Submisi token `picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `academy{...}` ditolak dengan `correct: false`.

### Modul 2: ID 219 `riscy business` (Reverse Engineering, Hard, picoMini by redpwn)
- **Arsitektur & Batas Input:** Biner Linux 64-bit RISC-V ELF (RV64GC / RV64IMAFDC) dengan Partial RELRO, Stack Canary enabled, NX enabled, dan No PIE. Biner membaca string dari stdin, memprosesnya via fungsi pengacakan byte, dan membandingkannya dengan array target 65 byte.
- **Akar Kerentanan (CWE-200, CWE-327):** Fungsi scrambling tidak memiliki difusi global (avalanche effect). Karakter ke-$i$ hanya mempengaruhi luaran pada posisi $0 \le k \le i$ tanpa ketergantungan balik. Karakter benar dapat dipulihkan per byte secara linear dengan memantau register `$s1` dan `$a5` pada breakpoint emulasi QEMU (`qemu-riscv64-static -g 1234`), mereduksi kompleksitas dari $68^{51}$ menjadi $51 \times 68 = 3.468$ evaluasi.
- **Validasi Validator:** Submisi token `picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `academy{...}` ditolak dengan `correct: false`.

### Modul 3: ID 220 `breadth` (Reverse Engineering, Hard, picoMini by redpwn)
- **Arsitektur & Batas Input:** Biner ganda ELF 64-bit x86-64 PIE stripped (`breadth.v1` dan `breadth.v2`). Masing-masing biner berisi puluhan ribu fungsi umpan yang memuat string `picoCTF{...}` acak di `.rodata`.
- **Akar Kerentanan (CWE-200, CWE-697):** Obfuskasi disinformasi statis disaring melalui analisis diferensial biner (`radiff2` / `cmp -bl`). Ditemukan tepat satu modifikasi fungsional pada file offset `610382` (`0x9504e`): kondisi `cmp $0xd037803a, %rax` pada `breadth.v1` diubah menjadi `cmp $0x41bc73e, %rax` pada `breadth.v2`. Percabangan `je 0x95070` memuat pointer string via `%rip`-relative addressing (`lea 0xc0e91(%rip), %rdi`), mengekstrak token valid di `.rodata` offset `0x155ef8`.
- **Validasi Validator:** Submisi token `picoCTF{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}` menghasilkan **HTTP 201 Created (`correct: true`)**. Wrapper alternatif `academy{...}` ditolak dengan `correct: false`.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_186_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (555/555 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_204`: **PASS** (reproduksi deterministik exit 0, token terverifikasi cocok).
3. `solve_219`: **PASS** (reproduksi linear prefix oracle exit 0, token terverifikasi cocok).
4. `solve_220`: **PASS** (reproduksi targeted binary diffing exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (sesi REST sehat, ketiga modul terkonfirmasi HTTP 201 `correct: true` pada live API CyLab).
6. `writeup_documentation_audit`: **PASS** (ketiga berkas writeup memuat flag resmi terverifikasi dan stempel Batch 186).

Laporan lengkap tersimpan pada `batch_186_verification_report.json`.

---

## 6. Temuan Audit & Pelajaran Kurikulum LKS

1. **Konsistensi Wrapper Modul Backport Event:** Seluruh modul yang berasal dari event `picoMini by redpwn` secara konsisten mempertahankan format wrapper native `picoCTF{...}` pada basis data penilaian CyLab Academy. Standarisasi paksa ke `academy{...}` menyebabkan penolakan oleh validator platform (`correct: false`).
2. **Kepatuhan NIST SP 800-115 §4.3 (Controlled Validation):** Verifikasi live submission wajib mencatat respons HTTP 201 `correct: true` langsung dari validator API platform.
3. **Disiplin Rekonstruksi & Dokumentasi LKS:** Writeup kompetisi LKS menyajikan analisis mendalam (teori akar masalah, arsitektur sistem, langkah eksploitasi terstruktur, serta mitigasi defensif aplikatif) untuk mendukung kesiapan siswa dalam kategori *Incident Response*, *Hardening*, dan *Defensive Security*.
