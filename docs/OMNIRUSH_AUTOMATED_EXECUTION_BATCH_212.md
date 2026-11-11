# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 212

Tanggal: 11 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (360, 361, 362). Kelanjutan Audit Event picoCTF 2023 (18/42 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 212 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 212, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian sekuensial 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi kelanjutan modul event picoCTF 2023 (#360 msfroggenerator2, #361 No way out, #362 PcapPoisoning), menganalisis HTTP Parameter Pollution pada reverse proxy Traefik, arsitektur asset packaging Unity 3D, dan format paket PCAP RFC 793 |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan bypass origin pembatas sandbox browser headless & kondisi balapan navigasi (CWE-20 / CWE-79 / CWE-362), serialisasi teks rahasia pada asset scene biner tanpa proteksi integritas (CWE-312 / CWE-693), serta transmisi data sensitif tanpa enkripsi transport (CWE-319 / RFC 793 / NIST SP 800-115 § 4.2) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekayasa dan memperbarui skrip solver otomatis mandiri `solve_360_msfroggenerator2.py`, `solve_361_no_way_out.py`, dan `solve_362_pcap_poisoning.py`, serta membangun suite uji deterministik `test_batch_212_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 581/581 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform (HTTP 201 correct:true), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: pengerasan sandbox Chromium headless pada otomasi QA, teknik asset encryption dan anti-tamper biner permainan, serta metodologi inspeksi paket jaringan menggunakan Wireshark dan string carving |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada lingkungan VPS (`lionelsabdani36@gmail.com`).
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_212_harness.py`.
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

### Modul 1: ID 360 `msfroggenerator2` (Web Exploitation, Hard, picoCTF 2023)
- **Arsitektur & Batas Input:** Aplikasi microservices multi-container (OpenResty, Traefik, Node.js Puppeteer bot, Express API). Endpoint `/report` meneruskan kueri URI ke Traefik dan Puppeteer.
- **Akar Kerentanan (CWE-20 / CWE-79 / CWE-362 / NIST SP 800-115 § 4.2):**
  1. Traefik memperlakukan karakter titik koma (`;`) sebagai pemisah parameter kueri (HTTP Parameter Pollution). Injeksi `;url=$PAYLOAD` menimpa parameter URL target bot.
  2. Navigasi Data URI memicu pengunduhan berkas otomatis ke `file:///root/Downloads/exploit.html`. Membuka berkas lokal memungkinkan penyematan `<iframe src="file:///flag.txt"></iframe>`.
  3. Celah waktu (*timing window*) antara `page.screenshot()` dan `page.evaluate(fetch...)` dimanfaatkan via pengalihan `setTimeout` ke `http://openresty:8080`, mengeksfiltrasi tangkapan layar yang memuat bendera ke `/api/reports/get`.
- **Validasi Validator:** Submisi token live `academy{th3_fsf_mak3s_th3_b3st_s0ftwar3_1dced559}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 361 `No way out` (Reverse Engineering, Hard, picoCTF 2023)
- **Arsitektur & Batas Input:** Permainan 3D mandiri berbasis Unity Engine (`win.zip`, password `picoctf`). Pemain terkurung di dalam arena sempit dengan dinding collider tak terlihat.
- **Akar Kerentanan (CWE-312 / CWE-693 / NIST SP 800-115 § 4.2):**
  1. Serialisasi aset scene Unity (`pico_Data/level0`) menyimpan objek hierarki scene dan string teks 3D secara terbuka (*plaintext storage at rest*).
  2. Inspeksi statis biner scene asset `level0` mengekstrak langsung string token target: `WELCOME_TO_UNITY!!`.
  3. Secara alternatif, rakitan .NET klien `pico_Data/Managed/Assembly-CSharp.dll` dapat didekompilasi menggunakan dnSpy untuk menghapus pemeriksaan `isGrounded` pada `PlayerController.Update`, memberikan kemampuan lompat tak terbatas melompati dinding pembatas.
- **Validasi Validator:** Submisi token live `academy{WELCOME_TO_UNITY!!}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 362 `PcapPoisoning` (Forensics, Medium, picoCTF 2023)
- **Arsitektur & Batas Input:** Berkas tangkapan rekaman jaringan (`trace.pcap`) yang merekam komunikasi aliran TCP antar endpoint host.
- **Akar Kerentanan (CWE-319 / RFC 793 / NIST SP 800-115 § 4.2):**
  1. Transmisi data sensitif berlangsung melalui protokol TCP (RFC 793) tanpa lapisan enkripsi TLS/HTTPS (Cleartext Data In-Transit).
  2. Paket segmen TCP #507 memuat payload bendera secara terbuka tanpa enkripsi, kompresi, atau obfusikasi.
  3. Pemindaian byte stream biner secara langsung menggunakan regex `(?:academy|picoCTF)\{[^}]+\}` merekonstruksi token bendera dalam hitungan milidetik.
- **Validasi Validator:** Submisi token live `academy{P64P_4N4L7S1S_SU55355FUL_7a51913b}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_212_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (581/581 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_360`: **PASS** (reproduksi Traefik HPP & Puppeteer timing window exit 0, token cocok).
3. `solve_361`: **PASS** (reproduksi Unity level0 scene asset extraction exit 0, token cocok).
4. `solve_362`: **PASS** (reproduksi PCAP RFC 793 TCP payload stream carving exit 0, token cocok).
5. `live_evidence_probes`: **PASS** (katalog CyLab HTTP 200, penyerahan token modul 360, 361, 362 terverifikasi HTTP 201 Created `correct: true`).
6. `writeup_documentation_audit`: **PASS** (writeup memuat 5 bab LKS wajib, token resmi tervalidasi, kepatuhan anti-slop zero em dash terverifikasi 100%).
