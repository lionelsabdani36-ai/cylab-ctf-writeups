# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 208

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (346, 348, 349). Kelanjutan Audit Event picoCTF 2023 (6/42 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 208 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 208, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian sekuensial 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan event picoCTF 2023 (#346 babygame02, #348 FindAndOpen, #349 findme), menganalisis alur eksekusi live TCP soket 32-bit ELF, decoding covert channel pcap, dan penelusuran rantai redirect HTTP 302 |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan stack array out-of-bounds write & saved EIP hijack (CWE-129 / CWE-787), transmisi kredensial terbuka & ZipCrypto stream cipher (CWE-312 / CWE-327), serta kebocoran informasi melalui pengalihan rantai rute URL parameter (CWE-200 / CWE-598) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekayasa dan memperbarui skrip solver otomatis mandiri `solve_346_babygame02.py`, `solve_348_findandopen.py`, dan `solve_349_findme.py`, serta membangun suite uji deterministik `test_batch_208_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 577/577 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform (HTTP 201 correct:true), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: rekayasa tumpukan memori & mitigasi kompilator modern, analisis lalu lintas jaringan covert channel, dan audit intersepsi alur aplikasi web aman |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada lingkungan VPS (`lionelsabdani36@gmail.com`).
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_208_harness.py`.
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

### Modul 1: ID 346 `babygame02` (Binary Exploitation, Hard, picoCTF 2023)
- **Arsitektur & Batas Input:** Permainan labirin terminal berbasis ASCII grid $30 \times 90$ yang dikompilasi sebagai biner ELF 32-bit x86.
- **Akar Kerentanan (CWE-129 / CWE-787 / NIST SP 800-115 § 4.2):**
  1. Subrutin `move_player()` memodifikasi koordinat pemain tanpa validasi batas bawah atau atas.
  2. Slot alamat kembali (`saved EIP`) `move_player()` berada pada `ebp_main - 0xab4`, dengan jarak relatif $-39$ byte dari buffer `map` (`ebp_main - 0xa95`).
  3. Memposisikan pemain pada `col = 51` (47 langkah `'d'`), mengubah karakter ubin ke `0x60` via perintah `'l'`, dan melangkah mundur ke `row = -1` (5 langkah `'w'`) menghasilkan offset $(-1 \times 90) + 51 = -39$.
  4. Instruksi `ret` dari `move_player()` membajak alur kontrol langsung ke fungsi `win()` (`0x08049760`), mencetak bendera langsung dari kontainer.
- **Validasi Validator:** Submisi token live `academy{gamer_jump1ng_4r0unD_5bc4b2bd}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 348 `FindAndOpen` (Forensics, Medium, picoCTF 2023)
- **Arsitektur & Batas Input:** Analisis tangkapan lalu lintas jaringan format libpcap (`dump.pcap`) dan arsip terproteksi ZIP (`flag.zip`).
- **Akar Kerentanan (CWE-312 / CWE-327 / NIST SP 800-115 § 4.2):**
  1. Pengiriman paket Ethernet mentah memuat string Base64 terselubung (`VGhpcyBpcyB0aGUgc2VjcmV0Oi...`).
  2. Dekode menghasilkan teks `This is the secret: academy{R34DING_LOKd_`, yang merupakan kata sandi arsip `flag.zip` dan bukan token akhir.
  3. Dekripsi kontainer ZipCrypto membuka berkas `flag` (45 byte) secara deterministik.
- **Validasi Validator:** Submisi token `academy{R34DING_LOKd_fil56_succ3ss_9989a41b}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 349 `findme` (Web Exploitation, Medium, picoCTF 2023)
- **Arsitektur & Batas Input:** Aplikasi web perbankan Node.js Express dengan autentikasi formulir `/login` (`test` / `test!`).
- **Akar Kerentanan (CWE-200 / CWE-598 / RFC 7231 / NIST SP 800-115 § 4.2):**
  1. Respon autentikasi menghasilkan HTTP 302 Found dengan header `Location: /next-page/id=YWNhZGVteXtwcm94aWVzX2Fs`.
  2. Halaman perantara mengeksekusi skrip timer JavaScript sisi klien yang mengalihkan rute ke `/next-page/id=bF90aGVfd2F5XzY2MWZjMzk4fQ==`.
  3. Dekode Base64 kedua fragmen URL menghasilkan `academy{proxies_al` dan `l_the_way_661fc398}` yang digabungkan menjadi token utuh.
- **Validasi Validator:** Submisi token `academy{proxies_all_the_way_661fc398}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_208_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (577/577 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_346`: **PASS** (reproduksi eksploitasi stack out-of-bounds return hijack exit 0, token cocok).
3. `solve_348`: **PASS** (reproduksi pcap covert channel & ZipCrypto decrypt exit 0, token cocok).
4. `solve_349`: **PASS** (reproduksi penelusuran rantai pengalihan HTTP 302 exit 0, token cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/picoCTF-2023/`, zero em dash).
