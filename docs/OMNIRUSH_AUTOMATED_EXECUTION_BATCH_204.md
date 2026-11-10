# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 204

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 § 4.2 (analisis kerentanan), § 4.3 (validasi terkontrol), § 4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (276, 277, 278). Kelanjutan Event picoCTF 2022 (26/65 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 204 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin audit sprint batch 204, menegakkan kepatuhan standar NIST SP 800-115, memverifikasi aturan anti-slop (zero em dash), sinkronisasi git, serta penyelesaian sekuensial 3 modul berurutan |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul lanjutan event picoCTF 2022 (#276 Keygenme, #277 Live Art, #278 Local Authority), memverifikasi artefak biner ELF 64-bit keygenme, aplikasi web React 17 / Vite drawing canvas, serta portal PHP login |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis kerentanan perbandingan digest MD5 pada stack frame (CWE-208 / CWE-312), W3C Custom Elements 'is' attribute sanitization bypass pada React JSX (CWE-79 / CWE-20), dan kegagalan otentikasi sisi klien JavaScript (CWE-603 / CWE-798 / OWASP A07) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Merekayasa dan memperbarui skrip solver otomatis mandiri `solve_276_keygenme.py`, `solve_277_live_art.py`, dan `solve_278_local_authority.py`, serta membangun suite uji deterministik `test_batch_204_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi verifikasi live `POST /api/submissions/` dengan CSRF token, sweep AST 573/573 skrip Python tanpa regresi sintaks, evaluasi penerimaan token platform (HTTP 201 correct:true), dan validasi integritas JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun takeaway kurikulum bimbingan teknis LKS Cyber Security: metodologi rekayasa balik keygen biner kompilasi, teknik audit sanitasi DOM frontend modern, serta tata kelola otentikasi aman berbasis sesi server |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada lingkungan VPS (`lionelsabdani36@gmail.com`).
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_204_harness.py`.
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

### Modul 1: ID 276 `Keygenme` (Reverse Engineering, Hard, picoCTF 2022)
- **Arsitektur & Batas Input:** Biner ELF 64-bit Linux x86-64 dinamis dengan OpenSSL libcrypto (`keygenme`, unstripped). Program membatasi masukan lisensi tepat 36 karakter melalui `fgets(buf, 0x25, stdin)`.
- **Akar Kerentanan (CWE-208 / CWE-312 / NIST SP 800-115 § 4.3):**
  1. Konstanta awalan lisensi sepanjang 27 karakter disematkan langsung dalam biner: `academy{br1ng_y0ur_0wn_k3y_`.
  2. Fungsi `check_key` menghitung hash MD5 dari awalan dan akhiran (`}`), lalu mengambil 8 karakter heksadesimal dinamis dari indeks tertentu pada digest MD5.
  3. Ketiadaan kriptografi asimetris memungkinkan generator kunci (keygen) mandiri dibangun dengan presisi 100%.
- **Validasi Validator:** Submisi token `academy{br1ng_y0ur_0wn_k3y_5b5d983e}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 277 `Live Art` (Web Exploitation, Hard, picoCTF 2022)
- **Arsitektur & Batas Input:** Aplikasi web single-page application (SPA) berbasis React 17 dan Vite dengan bot peninjau internal Chromium (Puppeteer) yang menyimpan bendera di `localStorage.username` origin `http://localhost:4000/`.
- **Akar Kerentanan (CWE-79 / CWE-20 / NIST SP 800-115 § 4.3):**
  1. Komponen `Viewer` mengurai parameter hash URL via `useHashParams()` dan menyebarkannya langsung ke elemen `<img src={props.image} {...dimensions} {...params} />`.
  2. Adanya atribut W3C Custom Element `is` memicu cabang `isCustomComponent` pada parser React DOM, memotong mekanisme sanitasi JSX standar dan meneruskan string `onerror` langsung ke atribut DOM mentah.
  3. Iframe eksploitasi memicu event `onerror` pada pemuatan gambar gagal, mengekstrak data sensitif dari `localStorage`, dan mengirimkannya keluar melalui beacon HTTP.
- **Validasi Validator:** Submisi token `academy{beam_me_up_reacty_cc2d3a25}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 278 `Local Authority` (Web Exploitation, Easy, picoCTF 2022)
- **Arsitektur & Batas Input:** Portal otentikasi web Apache/PHP yang memvalidasi username dan password pelanggan.
- **Akar Kerentanan (CWE-603 / CWE-798 / OWASP A07 / NIST SP 800-115 § 4.3):**
  1. Verifikasi kredensial dilakukan di lapisan JavaScript peramban (`secure.js`) dengan nilai kredensial statis `admin` : `strongPassword098765`.
  2. Keberhasilan validasi klien memicu pengisian form tersembunyi dengan hash statis `2196812e91c29df34f5e217cfd639881` yang diposting langsung ke `admin.php`.
  3. Ketiadaan verifikasi sesi di sisi server memungkinkan bypass autentikasi total dengan mengirimkan hash langsung via HTTP POST.
- **Validasi Validator:** Submisi token `academy{j5_15_7r4n5p4r3n7_28ad420c}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_204_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (573/573 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_276`: **PASS** (reproduksi keygen biner ELF exit 0, token cocok).
3. `solve_277`: **PASS** (reproduksi React Custom Elements XSS exit 0, token cocok).
4. `solve_278`: **PASS** (reproduksi bypass otentikasi login JavaScript exit 0, token cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/picoCTF-2022/`, zero em dash).
