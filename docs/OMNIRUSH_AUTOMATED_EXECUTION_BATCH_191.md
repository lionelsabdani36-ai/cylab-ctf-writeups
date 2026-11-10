# Omnirush Automated Solver Execution & Live Test Harness Audit - Batch 191

Tanggal: 10 November 2026 (UTC) | Akun siswa: Arielwin (user id `1072359`) | Platform: learn.cylabacademy.org
Standar Acuan: NIST SP 800-115 §4.2 (analisis kerentanan), §4.3 (validasi terkontrol), §4.4 (dokumentasi)
Kurikulum Sasaran: Persiapan Lomba LKS Cyber Security Nasional 2026
Kuota Run: MAKSIMAL 3 modul. Realisasi: **3 modul tuntas** (89, 90, 92). Penuntasan Event picoCTF 2020 Mini-Competition (6/6 modul).

---

## 1. Lanskap Orkestrasi Tim AI (David & AI Team)

Orkestrasi alur kerja terstruktur via papan Kanban AI Team:

| Agen | Peran | Kontribusi Teknis pada Batch 191 |
| :--- | :--- | :--- |
| David (Leader / Agent Nyawit) | Orkestrasi Tim & Arsitektur | Memimpin penuntasan audit sprint event picoCTF 2020 Mini-Competition (#89, #90, #92), kepatuhan NIST SP 800-115, dan integrasi repositori |
| Charlie (trend-hunter) | Recon & Triage Katalog | Mengidentifikasi modul penutup backlog pada event `picoCTF 2020 Mini-Competition` yang memerlukan re-audit standar LKS dan verifikasi wrapper platform |
| Athena (security-engineer) | Root Cause & Security Audit | Analisis format string leak & 32-bit ret2libc stack smashing (CWE-134/120), 64-bit ret2syscall ROP via unseeded PRNG prediction (CWE-330/120), dan inversi kendala mesin keadaan OTP jumble 4-bit nibble (CWE-327/330) |
| Alex (fullstack-dev) | Solver Remediation & Harness | Memperbarui skrip solver `solve_89`, `solve_90`, `solve_92` dengan mode reproduksi offline deterministik dan membangun suite uji test harness `test_batch_191_harness.py` |
| Julius (qa-engineer) | QA & Live Validation Gate | Mengeksekusi live `POST /api/submissions/` dengan CSRF token, sweep AST 560/560 skrip Python tanpa regresi, dan validasi JSON report |
| Judith (guru) | Kurikulum Pedagogis LKS | Menyusun materi kurikulum LKS: mitigasi format string GCC, penguatan proteksi biner (Canary, NX, PIE), isolasi CSPRNG Linux (`getrandom`), dan implementasi standar OTP/AES |

---

## 2. Status Eksekutor Otomatis (Omnirush CLI)

- **Status CLI:** `/usr/bin/omnirush` v2.7.1 terpasang pada VPS.
- **Integritas Pelaporan:** Eksekusi otomasi kode dipadukan dengan test harness deterministik Python `scripts/test_batch_191_harness.py`.
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

### Modul 1: ID 89 `guessing-game-2` (Binary Exploitation, Hard, picoCTF 2020 Mini-Competition)
- **Arsitektur & Batas Input:** Biner ELF 32-bit x86 (`guessing-game-2-vuln`) dengan Partial RELRO, Canary, NX, dan No PIE (basis 0x08048000). Alamat fungsi internal: `puts@plt` = `0x08049090`, `puts@got` = `0x0804bfe0`, `win` = `0x0804931e`.
- **Akar Kerentanan (CWE-134 / CWE-120 / CWE-330):**
  1. Formula `(get_random() % 4096) + 1` mengevaluasi pointer fungsi `rand` di libc. Pada glibc 32-bit lingkungan kontainer, evaluasi menghasilkan jawaban deterministik `-2623`.
  2. Fungsi `printf(winner)` pada `win()` memicu format string leak. Posisi argumen posisional `%135$p` mengekfiltrasi nilai 32-bit Stack Canary tanpa merusak eksekusi.
  3. `gets(winner)` membaca tanpa batas ke buffer 512 byte (`ebp - 0x20c`). Rantai ROP disusun dengan meletakkan kembali nilai canary pada offset 512, melewati 12 byte padding, lalu mengontrol saved EIP (offset 528).
  4. ROP Tahap 1 memanggil `puts(puts_got)` untuk membocorkan basis libc dan kembali ke `win()`. ROP Tahap 2 memanggil `system("/bin/sh")`.
- **Rektifikasi & Validasi Validator:** Token statis lama `506b81e98597929e` ditolak validator (`correct: false`). Eksploitasi kontainer live menghasilkan bendera resmi `academy{p0p_r0p_4nd_dr0p_1t_7e7a20729a190e8d}` yang terverifikasi **HTTP 201 Created (`correct: true`)**.

### Modul 2: ID 90 `guessing-game-1` (Binary Exploitation, Medium, picoCTF 2020 Mini-Competition)
- **Arsitektur & Batas Input:** Biner ELF 64-bit x86-64 kompilasi statis (`guessing-game-1-vuln`) dengan Partial RELRO, No Canary, NX, dan No PIE (basis 0x400000). Memori writable `.bss` terletak di `0x4c9360`.
- **Akar Kerentanan (CWE-330 / CWE-120):**
  1. Pemanggilan `rand() % 100 + 1` tanpa `srand()` menyebabkan glibc menggunakan seed default 1, menghasilkan tebakan deterministik pertama selalu bernilai 84.
  2. `fgets(winner, 360, stdin)` pada frame stack 0x70 (112 byte) tanpa stack protector menimpa saved RBP (offset 112) dan saved RIP tepat pada offset 120.
  3. Biner statis menyediakan gadget libc tetap: `pop rdi; ret` (0x40206f), `pop rsi; pop r15; ret` (0x40206d), `pop rax; pop rdx; pop rbx; ret` (0x486bba), `syscall; ret` (0x41b406), `__libc_read` (0x450e80).
  4. ROP Tahap 1 mengeksekusi `read(0, BSS, 0x180)` lalu pivot ke `BSS`. ROP Tahap 2 menempatkan `/bin/sh\x00` pada `BSS` dan mengeksekusi `execve(BSS, NULL, NULL)` via `syscall` (rax=59).
- **Validasi Validator:** Submisi token `academy{r0p_y0u_l1k3_4_hurr1c4n3_3ea9d94813b570b2}` menghasilkan **HTTP 201 Created (`correct: true`)**.

### Modul 3: ID 92 `otp-implementation` (Reverse Engineering, Hard, picoCTF 2020 Mini-Competition)
- **Arsitektur & Batas Input:** Biner ELF 64-bit Linux (`otp`) dan berkas ciphertext terenkripsi 50 byte (`enc_flag.txt`). Biner memvalidasi kunci heksadesimal 100 karakter pengguna melalui fungsi `jumble()` terhadap string kendala statis `ct`.
- **Akar Kerentanan (CWE-327 / CWE-330):**
  1. Ruang keadaan kunci tereduksi menjadi 4-bit nibble (`comp = (prev + jumble(c)) % 16`).
  2. Karena alfabet masukan hanya mencakup 16 karakter heksadesimal (`0-9`, `a-f`) dan dependensi transisi bersifat linear tanpa percabangan ganda, kunci dapat direkonstruksi secara greedy dalam $O(16 \cdot 100) = 1.600$ iterasi.
  3. Memulihkan kunci heksadesimal 100 karakter dan mendekripsi ciphertext 50 byte via operasi bitwise XOR menghasilkan flag plaintext.
- **Validasi Validator:** Submisi token `academy{cust0m_jumbl3s_4r3nt_4_g0Od_1d3A_731cd140}` menghasilkan **HTTP 201 Created (`correct: true`)**.

---

## 5. Hasil Uji Test Harness (`scripts/test_batch_191_harness.py`)

Eksekusi suite uji menghasilkan status **ALL PASSED (6/6 checks)**:

1. `ast_syntax_sweep`: **PASS** (560/560 file skrip Python tervalidasi AST tanpa kesalahan sintaks).
2. `solve_89`: **PASS** (reproduksi format string canary leak & ret2libc exit 0, token terverifikasi cocok).
3. `solve_90`: **PASS** (reproduksi ret2syscall ROP & PRNG prediction exit 0, token terverifikasi cocok).
4. `solve_92`: **PASS** (reproduksi inversi jumble state machine exit 0, token terverifikasi cocok).
5. `live_evidence_probes`: **PASS** (konektivitas sehat HTTP 200, penyerahan flag live HTTP 201 `correct: true` untuk ketiga modul).
6. `writeup_documentation_audit`: **PASS** (berkas writeup LKS dan token resmi tervalidasi lengkap di `writeups/picoCTF-2020-Mini-Competition/`).
