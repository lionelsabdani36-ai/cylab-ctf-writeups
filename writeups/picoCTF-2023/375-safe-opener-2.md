# Writeup: Safe Opener 2 (Challenge ID: 375)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Java Bytecode & Constant Pool
- **Difficulty:** Medium (diff=2)
- **Event:** picoCTF 2023
- **Flag:** `academy{SAf3_0p3n3rr_y0u_solv3d_it_7f70e636}`

---

## Problem Statement & Scope

Tantangan menyediakan file biner bytecode Java yang telah terkompilasi (`SafeOpener.class`). Pengguna kehilangan kunci brankas (safe key) dan ditugaskan merekonstruksi kunci valid dari artefak biner yang tersedia tanpa source code awal (`.java`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **JVM Class File Format & Constant Pool (JVM Specification SE / NIST SP 800-115):** File `.class` Java diawali dengan magic byte `0xCAFEBABE`. Semua literal konstanta, referensi nama kelas, metode, serta string plaintext disimpan secara eksplisit pada struktur `cp_info` (Constant Pool) dengan tag `CONSTANT_Utf8` (`tag 1`).
2. **Hardcoded Secrets in Client/Compiled Binaries:** Menyimpan kredensial otentikasi atau kunci rahasia dalam bentuk literal statis di dalam kode sumber compiled binary memungkinkan penyerang mengekstrak rahasia tersebut tanpa perlu mendekompilasi penuh seluruh logika alur program.
3. **Pembedahan Biner:** String rahasia `academy{SAf3_0p3n3rr_y0u_solv3d_it_7f70e636}` terdaftar langsung sebagai entri string UTF-8 pada tabel konstanta JVM, terbaca dengan string analysis sederhana (`strings` / regex parser).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh artefak: `SafeOpener.class` dari CDN CyLab Academy (`challenge-files.cylabacademy.net/library/...`).
2. Inspeksi string statis pada file kelas:
   ```bash
   strings SafeOpener.class | grep -E "(academy|picoCTF)\{"
   ```
   Atau inspeksi tabel konstanta via `javap`:
   ```bash
   javap -v -constants SafeOpener.class
   ```
3. Ekstraksi otomatis melalui skrip `scripts/solve_375_safe_opener_2.py`.
4. Verifikasi token via REST API: `POST /api/submissions/` dengan payload `{"challenge": 375, "flag": "academy{SAf3_0p3n3rr_y0u_solv3d_it_7f70e636}"}` menghasilkan HTTP Status 201 `correct: true`.

---

## Flag & Verifikasi

- **Flag:** `academy{SAf3_0p3n3rr_y0u_solv3d_it_7f70e636}`
- **Bukti:** Submisi REST API `/api/submissions/` mengembalikan `{"correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS:** Penguasaan struktur format file JVM `.class`, penggunaan tool inspeksi bytecode (`javap`, decompilers CFR/Procyon), serta audit hardcoded credentials.
- **Mitigasi Defensif:** Jangan pernah menanam kredensial atau kunci rahasia di dalam biner sisi klien (client-side binary). Gunakan mekanisme challenge-response jarak jauh berbasis server (KMS/HSM) dan teknik *code obfuscation* bila proteksi integritas aplikasi diperlukan.
