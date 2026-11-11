# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 211

Tanggal: 11 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (356, 358, 359). Kelanjutan Audit Event picoCTF 2023 (15/42 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 211 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 211, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian sekuensial 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan event picoCTF 2023 (#356 MatchTheRegex, #358 More SQLi, #359 MSB), menganalisis pola ekspresi reguler klien-server, arsitektur SQLite embedded database, dan format bitplane PNG RFC 2083 |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan kebocoran logika validasi klien (CWE-200 / CWE-20), bypass otentikasi boolean & eksfiltrasi data via UNION SQL Injection (CWE-89 / OWASP A03), serta manipulasi steganografi bidang bit Most Significant Bit (CWE-200 / CWE-532 / NIST SP 800-115 § 4.2) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekayasa dan memperbarui skrip solver otomatis mandiri `solve_356_match_the_regex.py`, `solve_358_more_sqli.py`, dan `solve_359_msb.py`, serta membangun suite uji deterministik `test_batch_211_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 580/580 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform (HTTP 201 correct:true), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: sanitasi kode produksi front-end, implementasi parameterized queries (PDO/prepared statements) untuk pertahanan injeksi basis data, serta pemahaman defiltering format citra PNG RFC 2083 untuk forensik digital |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada lingkungan VPS (`lionelsabdani36@gmail.com`).
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_211_harness.py`.
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

### Modul 1: ID 356 `MatchTheRegex` (Web Exploitation, Medium, picoCTF 2023)
- **Arsitektur & Batas Input:** Aplikasi web interaktif pada kontainer on-demand yang menerima input formulir dan memvalidasinya terhadap regular expression pada backend via parameter GET `/flag?input=<val>`.
- **Akar Kerentanan (CWE-200 / CWE-20 / NIST SP 800-115 § 4.2):**
  1. Komentar pada kode sumber JavaScript front-end `send_request()` membocorkan pola ekspresi reguler target: `// ^a.....y!?`.
  2. Karakter anchor `^a` mewajibkan awalan huruf 'a', diikuti tepat 5 karakter acak (`.....`), dan diakhiri huruf 'y'.
  3. String masukan `academy` memenuhi seluruh kriteria regex secara presisi (panjang 7 karakter, diawali 'a', diakhiri 'y'). Pengiriman query `GET /flag?input=academy` meloloskan verifikasi backend dan menghasilkan respon JSON token resmi.
- **Validasi Validator:** Submisi token live `academy{succ3ssfully_matchtheregex_4d5352dc}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 358 `More SQLi` (Web Exploitation, Medium, picoCTF 2023)
- **Arsitektur & Batas Input:** Aplikasi web PHP dengan basis data embedded SQLite (`sqlite3`). Formulir login mengonkatensasi input string langsung ke dalam perintah SQL tanpa prepared statements. Formulir pencarian kantor pada `welcome.php` mengembalikan 3 kolom data (`City`, `Address`, `Phone`).
- **Akar Kerentanan (CWE-89 / OWASP A03 / NIST SP 800-115 § 4.2):**
  1. Query otentikasi login rentan terhadap SQL Injection: `SELECT id FROM users WHERE password = '$password' AND username = '$username'`.
  2. Injeksi string `' OR 1=1 -- ` pada field password mengubah klausul WHERE menjadi selalu benar (`TRUE`) dan memotong sisa query melalui sintaks komentar sebaris SQLite (`-- `), mengizinkan login tanpa otentikasi kredensial valid.
  3. Formulir pencarian `welcome.php` rentan terhadap UNION-based SQL Injection 3 kolom. Injeksi `' UNION SELECT tbl_name, sql, 3 FROM sqlite_master -- ` membocorkan keberadaan tabel tersembunyi `more_table` berskema `(id INTEGER PRIMARY KEY, flag TEXT)`.
  4. Injeksi `' UNION SELECT flag, id, 3 FROM more_table -- ` mengekstrasi token kompetisi secara langsung ke dalam tabel HTML antarmuka pengguna.
- **Validasi Validator:** Submisi token live `academy{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_b5ff84c8}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 359 `MSB` (Forensics, Medium, picoCTF 2023)
- **Arsitektur & Batas Input:** Analisis artefak grafis citra digital ukiyo-e Jepang format Portable Network Graphics (PNG) 24-bit (`Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisada.flag.png`), resolusi 1074x1500 piksel. Uji statistik LSB standar menghasilkan nilai negatif.
- **Akar Kerentanan (CWE-200 / CWE-532 / NIST SP 800-115 § 4.2):**
  1. Steganografi spasial non-konvensional: data tersembunyi disematkan pada Most Significant Bit (MSB / bit 7) dari masing-masing kanal warna RGB (Red, Green, Blue), memicu variasi kontras visual sebesar 128 intensitas warna.
  2. Berdasarkan spesifikasi RFC 2083, baris pemindaian (scanline) PNG dikompresi setelah proses filtering baris (tipe 0: None, 1: Sub, 2: Up, 3: Average, 4: Paeth). Untuk memperoleh nilai kanal piksel mentah, analis merekonstruksi defiltering prediktif baris demi baris menggunakan algoritma Paeth RFC 2083.
  3. Pengambilan bit ke-7 dari setiap kanal byte yang telah didefilter dan penggabungan setiap 8 bit (MSB-first) merekonstruksi teks ASCII yang memuat pola token resmi.
- **Validasi Validator:** Submisi token live `academy{15_y0ur_que57_qu1x071c_0r_h3r01c_80119e7f}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_211_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (580/580 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_356`: **PASS** (reproduksi validasi regex anchor `^a.....y` exit 0, token cocok).
3. `solve_358`: **PASS** (reproduksi SQLite auth bypass & UNION exfiltration exit 0, token cocok).
4. `solve_359`: **PASS** (reproduksi PNG RFC 2083 scanline defiltering & MSB bitplane extraction exit 0, token cocok).
5. `live_evidence_probes`: **PASS** (katalog CyLab HTTP 200, penyerahan token modul 356, 358, 359 terverifikasi HTTP 201 Created `correct: true`).
6. `writeup_documentation_audit`: **PASS** (writeup memuat 5 bab LKS wajib, token resmi tervalidasi, kepatuhan anti-slop zero em dash terverifikasi 100%).
