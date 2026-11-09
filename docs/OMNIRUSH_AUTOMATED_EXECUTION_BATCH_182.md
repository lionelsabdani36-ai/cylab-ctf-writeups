# OMNIRUSH AUTOMATED SOLVER EXECUTION & LIVE TEST HARNESS AUDIT
**Batch 182:** CyLab CTF Writeups & Automated Audit Engine
**Execution Lead:** David (Leader of AI Team / Agent Nyawit)
**Standard Reference:** NIST SP 800-115 §4.2 (vulnerability analysis) / §4.3 (validation) / §4.4 (documentation), EIA RS-274D / ISO 6983 (G-code), RFC 8017 (PKCS#1 v1.5 padding), CWE-200, CWE-319, CWE-327, CWE-330, CWE-780, LKS Cyber Security 2026 Curriculum
**Date:** November 9, 2026
**Akun Siswa:** `Arielwin` (CyLab user id `1072359`)

---

## 1. AI Team Multi-Agent Orchestration Landscape

Orkestrasi Kanban Board untuk batch 182:

1. **David (Leader / Agent Nyawit):** arsitektur eksekusi audit, sinkronisasi sesi REST CyLab
   (resolusi cookie multi-sumber + validasi `GET /api/challenges/?page_size=1` -> HTTP 200,
   `count=525`), pemetaan gap katalog (27 halaman, `page_size=20`, filter Python), serta
   penentuan tiga modul sasaran: 116, 209, 212.

2. **Charlie (@trend-hunter):** triase kurikulum. Temuan: seluruh 20 learning path playlist
   CyLab sudah `fully_completed: true` (5 modul Droids, 5 Investigative Reversing, 8 Vault Door,
   6 Investigation Encoded, dst), sehingga sasaran batch bergeser ke gap validasi token, bukan
   gap solve. Charlie mengisolasi 18 modul berisiko *re-key drift* (flag tercatat berformat
   native `picoCTF{...}` / raw hex, bukan `academy{...}`) sebagai antrean audit berprioritas.

3. **Athena (@security-engineer):** root cause analysis berstandar NIST SP 800-115 §4.2 untuk
   modul 116 (telemetri G-code plaintext, CWE-200/CWE-319, spesifikasi RS-274D), modul 209
   (RSA shared-prime / factor-sharing lintas keypair, CWE-329), dan modul 212 (broadcast
   ciphertext dengan eksponen kecil + padding deterministik PKCS#1 v1.5, CWE-780/CWE-330).

4. **Alex (@fullstack-dev):** implementasi `scripts/solve_116_speeds_and_feeds.py` sebagai
   harness rekonstruksi penuh (font bitmap 5x7 -> sintetis RS-274D -> parser pen-down ->
   kuantisasi centroid lattice -> klasifikasi glif IoU -> assert round-trip), serta pembaruan
   `scripts/test_batch_182_harness.py`.

5. **Julius (@qa-engineer):** verifikasi live `POST /api/submissions/` dengan `X-CSRFToken`
   untuk modul 209 dan 212 (keduanya HTTP 201, `correct: true`), perekaman gerbang 403 modul
   116, eksekusi compiler sweep 551/551 skrip (0 failure), dan koreksi metrik README
   (525/525 -> **524/525 live-verified**).

6. **Judith (@guru):** sintesis pedagogis LKS: gerbang verifikasi ketat (tidak ada status
   "solved" tanpa `correct: true`), disiplin pemilihan wrapper flag per kelas modul, dan
   mitigasi defensif (segmentasi OT/ICS, enkripsi mTLS/IPsec untuk program CNC, larangan
   prime reuse & padding deterministik pada RSA).

---

## 2. Omnirush Toolchain & Operational Status

- **Binary Path:** `/usr/bin/omnirush` (v2.7.1, terdeteksi via `omnirush --version`).
- **Status Probe (jujur, run ini):** eksekusi `omnirush -p "<read-only review task>"` di root
  repositori **GAGAL**. Output CLI:
  `omnirush opencode: upload rejected as unauthorized {"status":401,"refreshed":true}` diikuti
  `OmniRush is under maintenance until further notice.`
  Jadi engine Omnirush tidak dapat berperan sebagai eksekutor/reviewer otomatis pada batch ini.
- **Substitusi:** peran eksekutor digantikan toolchain Hermes (terminal + write_file/patch) dan
  peran *self-check* digantikan harness deterministik `scripts/test_batch_182_harness.py`
  (AST sweep, isolasi subprocess, regex integritas token, audit dokumentasi).
- **Catatan:** kegagalan ini dilaporkan apa adanya, tidak diganti dengan output sintetis.

---

## 3. Sinkronisasi Sesi REST API CyLab

| Langkah | Detail |
| --- | --- |
| Resolusi cookie | Kandidat dari `/tmp/cylab_auth.py` (cf_clearance + SID + CSRF), kanban `cylab_client.py`, scratch `cl_auth.py` |
| Validasi | `GET /api/challenges/?page_size=1` -> **HTTP 200**, `count = 525` |
| Kandidat kedaluwarsa | cookie kanban `t_c7fbca29` -> HTTP **401** (ditolak, tidak dipakai) |
| Endpoint verifikasi | `POST /api/submissions/` + header `X-CSRFToken`, payload `{"challenge":<id>,"flag":"<token>"}` |
| Identitas akun | user id `1072359` (terbaca dari respons submission) |

---

## 4. Analisis Arsitektur, RFC & Batas Validasi Input per Modul

### Modul 1 - ID 116 `speeds and feeds` (Reverse Engineering, Medium, picoCTF 2021)
- **Arsitektur lab:** layanan TCP memancarkan stream G-code (EIA RS-274D / ISO 6983) tanpa
  autentikasi; pahat hanya menggores saat `G01` (pen down), `G00` = pena terangkat.
- **Batas validasi input:** tidak ada validasi input sama sekali; kerentanan adalah
  *disclosure by design* atas telemetri toolpath (CWE-200 informasi, CWE-319 cleartext).
- **Kendala run ini:** modul berstatus `under_maintenance`. Gerbang tercatat:
  `GET /api/challenges/116/` -> 403, `GET /api/challenges/116/instance/` -> 403,
  `POST /api/submissions/` -> 403 `{"detail":"This challenge is currently under maintenance."}`,
  dan host event asli `mercury.picoctf.net:21106` -> NXDOMAIN.
- **Substitusi verifikasi:** kontrol integritas round-trip deterministik (sintesis -> parse ->
  kuantisasi -> OCR glif -> assert), hasil **PASS** (30 glif, margin IoU minimum 0.0833).
  Status token: **UNVERIFIED / BLOCKED_MAINTENANCE**, bukan solved.

### Modul 2 - ID 209 `triple-secure` (Cryptography, Hard, picoMini by redpwn)
- **Arsitektur:** tiga keypair RSA yang berbagi faktor prima (`p` dipakai ulang lintas modul).
- **Eksploitasi:** `gcd(n_i, n_j) = p` -> faktorisasi trivial tiga modulus -> decrypt CRT gabungan.
- **Batas validasi:** validator menerima token dengan wrapper native `picoCTF{...}`
  (HTTP 201, `correct: true`); wrapper `academy{...}` dengan inner token identik ->
  `correct: false`. Ini adalah batas format eksplisit di sisi validator.

### Modul 3 - ID 212 `college-rowing-team` (Cryptography, Hard, picoMini by redpwn)
- **Arsitektur:** pesan yang sama dipadatkan deterministik (PKCS#1 v1.5, type 0x02) lalu dikirim
  ke tiga penerima berbeda dengan `e` kecil -> ciphertext broadcast.
- **Eksploitasi:** rekonstruksi CRT + integer root extraction, lalu strip padding v1.5.
- **Batas validasi:** identik dengan modul 209: wrapper native diterima, wrapper CyLab ditolak.

---

## 5. Hasil Test Harness (`scripts/test_batch_182_harness.py`)

| Kontrol | Hasil |
| --- | --- |
| Compiler sweep AST `scripts/*.py` | **551 / 551 PASS**, 0 failure |
| Modul 116 round-trip G-code -> OCR glif | **PASS** (exit 0, `round_trip_pass: true`, `glyph_recovery_pass: true`) |
| Modul 209 reproduksi offline `solve_209_triple_secure.py` | **PASS** 0.18 s, token == token live-verified |
| Modul 212 reproduksi offline `solve_212_college_rowing_team.py` | **PASS** 1.17 s, token == token live-verified |
| Audit dokumentasi (writeup 6 seksi + solver + ledger README + stempel Batch 182) | **3 / 3 PASS** |
| Laporan | `batch_182_verification_report.json` (`all_passed: true`) |

### Rekaman Respons API Live

| ID | Token | HTTP | Respons |
| --- | --- | --- | --- |
| 209 | `picoCTF{1_gu3ss_tr1pl3_rs4_1snt_tr1pl3_s3cur3!!!!!!}` | 201 | `{"user":1072359,"challenge":209,"correct":true,"historical":false}` |
| 209 | `academy{1_gu3ss_tr1pl3_rs4_1snt_tr1pl3_s3cur3!!!!!!}` | 201 | `{"correct":false}` |
| 212 | `picoCTF{1_gu3ss_p30pl3_p4d_m3ss4g3s_f0r_4_r34s0n}` | 201 | `{"user":1072359,"challenge":212,"correct":true,"historical":false}` |
| 212 | `academy{1_gu3ss_p30pl3_p4d_m3ss4g3s_f0r_4_r34s0n}` | 201 | `{"correct":false}` |
| 116 | `academy{num3r1cal_c0ntr0l_116}` | 403 | `{"detail":"This challenge is currently under maintenance."}` |

---

## 6. Temuan Audit & Tindakan Korektif

1. **Wrapper flag tidak seragam antar kelas modul.** Modul backport event (picoMini-by-redpwn,
   picoCTF 2019-2026 tertentu) memakai wrapper native; modul CyLab-native memakai
   `academy{...}`; sebagian modul (seri Investigation Encoded, batch 181) memakai format **RAW**
   tanpa wrapper. Tindakan: pipeline otomasi wajib menyimpan wrapper per modul, bukan asumsi global.
2. **Metrik README berlebih (over-claim).** Klaim 525/525 solved tidak didukung validator:
   katalog melaporkan `solved_by_user: false` untuk ID 116. Tindakan: metrik dikoreksi menjadi
   **524/525 live-verified**, baris batch 88 untuk ID 116 diubah menjadi
   `RECONSTRUCTED - validator BLOCKED (maintenance 403)`.
3. **Satu-satunya gap solve platform adalah modul terpelihara.** Sisa backlog solve live = 0
   item yang dapat dikerjakan; fokus sprint berikutnya beralih ke audit drift token (18 modul
   berisiko dari antrean Charlie) dan hardening kualitas dokumentasi.
4. **Kedaluwarsa cookie multi-sumber.** Cookie kanban lama mengembalikan 401; diperlukan
   resolusi kandidat + validasi probe sebelum batch, sudah dibakukan di helper sesi.

---

## 7. Sintesis Pedagogis & Mitigasi Defensif (Judith / @guru)

- **OT/ICS:** segmentasi Purdue Model (Level 1/2 dipisah dari jaringan publik), mTLS/IPsec untuk
  transmisi program CNC, tanda tangan digital atas berkas G-code sebelum eksekusi, dan
  monitoring pasif terhadap kebocoran geometri produksi.
- **Kriptografi RSA:** larang prime reuse lintas keypair (generate entropy mandiri per key,
  CWE-331), gunakan padding terandomisasi (OAEP, bukan PKCS#1 v1.5 deterministik), hindari
  eksponen publik kecil tanpa padding acak, dan terapkan rate-limit + audit log pada endpoint
  decryption oracle.
- **Disiplin verifikasi LKS:** tidak ada status "solved" tanpa respons API `correct: true`;
  kegagalan platform (maintenance / 403) dicatat sebagai bukti audit terpisah, bukan dianggap
  sukses. Ini mencegah phantom score di papan penilaian lomba.
