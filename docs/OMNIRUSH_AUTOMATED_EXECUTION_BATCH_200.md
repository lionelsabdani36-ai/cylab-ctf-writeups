# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 200

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (264, 265, 266). Kelanjutan Event picoCTF 2022 (14/65 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 200 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 200, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian tuntas 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan event picoCTF 2022 (#264 Eavesdrop, #265 Enhance!, #266 file-run1), memverifikasi ketersediaan artefak PCAP jaringan, grafis vektor XML SVG, dan biner eksekutabel ELF 64-bit |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan kebocoran kredensial saluran kontrol TCP tanpa proteksi transport (RFC 793 / CWE-319 / CWE-327), fragmentasi data sensitif pada DOM node XML SVG (CWE-200), dan penyimpanan string rahasia teks terbuka pada segmen biner .rodata (CWE-312 / CWE-798) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekayasa dan memperbarui skrip solver otomatis mandiri `solve_264_eavesdrop.py` (ekstraksi stream TCP & dekripsi OpenSSL DES3), memvalidasi `solve_265_enhance.py` dan `solve_266_file_run1.py`, serta membangun suite uji deterministik `test_batch_200_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 569/569 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform (HTTP 201 correct:true), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: metodologi Network Forensics (stream reassembly & packet carving), sanitasi metadata dokumen vektor SVG, tata kelola rahasia biner, dan penerapan mitigasi defensif TLS 1.3 |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada lingkungan VPS (`lionelsabdani36@gmail.com`).
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_200_harness.py`.
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

### Modul 1: ID 264 `Eavesdrop` (Forensics, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Rekaman jaringan PCAP (`capture.flag.pcap`, ~7.5 KB) merekam interaksi protokol Layer 4 TCP (RFC 793) tanpa lapisan keamanan transport. Dua percakapan paralel berlangsung pada port 9001 (saluran teks obrolan) dan port 9002 (transfer biner muatan terenkripsi).
- **Akar Kerentanan (CWE-319 / CWE-327 / NIST SP 800-115 § 5.2):**
  1. Penyaluran kata sandi bersama (`supersecretpassword123`) dan sintaks perintah dekripsi lengkap melalui saluran teks terbuka port 9001.
  2. Penggunaan cipher blok usang Triple-DES (DES3) yang rentan collision attack (Sweet32) dan telah didepresiasi oleh NIST SP 800-131A.
  3. Muatan berkas pada port 9002 diawali penanda format OpenSSL `Salted__` (48 bita). Dengan merekonstruksi segmen TCP stream port 9002 dan mengeksekusi `openssl des3 -d -salt -k supersecretpassword123`, token rahasia berhasil didekripsi.
- **Validasi Validator:** Submisi token `academy{nc_73115_411_02612719}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 265 `Enhance!` (Forensics, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Berkas citra grafik vektor berbasis XML Scalable Vector Graphics (`drawing.flag.svg`). Sesuai rekomendasi W3C, elemen visual dan teks SVG didefinisikan dalam struktur pohon markup XML (`<text>`, `<tspan>`, `<path>`).
- **Akar Kerentanan (CWE-200 / NIST SP 800-115 § 5.2):**
  1. Token rahasia disematkan secara terfragmentasi ke dalam sub-elemen `<tspan>` di bawah `<text id="text3720">`.
  2. Karakter token dipisahkan spasi dan baris baru serta diberi pergeseran koordinat tipografi lokal untuk mengelabui penampil citra raster biasa.
  3. Inspeksi langsung terhadap dokumen XML atau regex `<tspan>` mengekstrak seluruh fragmen karakter dan menghasilkan token utuh.
- **Validasi Validator:** Submisi token `academy{3nh4nc3d_001f8059}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 266 `file-run1` (Reverse Engineering, Medium, picoCTF 2022)
- **Arsitektur & Batas Input:** Biner eksekutabel ELF 64-bit x86-64 unstripped dynamically linked berukuran 16 KB (`run`). Modul menguji pemahaman perizinan POSIX dan tata letak string memori biner.
- **Akar Kerentanan (CWE-312 / CWE-798 / NIST SP 800-115 § 5.3):**
  1. Token rahasia dikompilasi secara langsung sebagai string teks terbuka ke dalam segmen data baca-saja `.rodata` tanpa proteksi enkripsi atau pengacakan runtime.
  2. Fungsi `main()` langsung mencetak string token saat biner dieksekusi melalui antarmuka baris perintah (`./run`).
  3. Token dapat diekstraksi secara statis via string scanning (`strings run`) maupun secara dinamis dengan memberikan hak eksekusi `chmod +x`.
- **Validasi Validator:** Submisi token `academy{U51N6_Y0Ur_F1r57_F113_4640f37e}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_200_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (569/569 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_264`: **PASS** (reproduksi live PCAP TCP stream extraction & OpenSSL DES3 decryption exit 0, token cocok).
3. `solve_265`: **PASS** (reproduksi SVG XML DOM parsing & text node extraction exit 0, token cocok).
4. `solve_266`: **PASS** (reproduksi ELF binary inspection & dynamic invocation exit 0, token cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/picoCTF-2022/`).
