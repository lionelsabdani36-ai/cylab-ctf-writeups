# Writeup: Static ain't always noise (Challenge ID: 163)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Binary String Extraction & Disassembly Analysis
- **Difficulty:** Easy (diff=1)
- **Author:** syreal
- **Event:** picoCTF 2021
- **Points:** 20
- **Flag:** `academy{d15a5m_t34s3r_fac3431a}`

---

## Problem Statement & Scope

Diberikan sebuah berkas biner ELF Linux 64-bit bernama `static` dan sebuah skrip pembantu bash bernama `ltdis.sh`. Deskripsi soal menanyakan: *"Can you look at the data in this binary? The bash script might help!"*.

Tantangan ini menguji pemahaman dasar peserta terkait arsitektur berkas biner compiled (format ELF), perbedaan antara instruksi mesin yang dapat dieksekusi (segmen `.text`) dan data statis (segmen `.rodata` / `.data`), serta metodologi ekstraksi informasi sensitif yang tertinggal dalam artefak biner (*binary artifacts analysis*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Biner Executable and Linkable Format (ELF):**
   - Berkas biner hasil kompilasi bahasa tingkat rendah (C/C++) diorganisasi ke dalam beberapa section dan segment memori. Bagian kode biner yang dieksekusi oleh CPU berada di section `.text`, sedangkan string literal dan konstanta statis dialokasikan pada section `.rodata` (read-only data).
   - Skrip pembantu `ltdis.sh` menunjukkan dua operasi dasar analisis biner:
     1. Disassembly instruksi: `objdump -Dj .text <file>`
     2. Ekstraksi urutan karakter ASCII cetak: `strings -a -t x <file>`
2. **Penyimpanan Kredensial Teks Polos (CWE-312 / CWE-200):**
   - Tanpa mekanisme proteksi, enkripsi konstanta (*string encryption*), atau obfuscation, setiap string sensitif yang dikompilasi ke dalam biner akan tersimpan sebagai barisan byte ASCII berurutan yang diakhiri null-byte (`\x00`).
   - Analis keamanan atau penyerang dapat mengekstraksi seluruh string tersebut secara instan tanpa perlu menjalankan program (*zero runtime execution requirement*), sehingga teknik ini menjadi fondasi awal uji penetrasi sistem berbasis NIST SP 800-115.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Skrip Pembantu (`ltdis.sh`):**
   Membaca isi skrip pembantu menggunakan utilitas pembaca berkas:
   ```bash
   cat ltdis.sh
   ```
   Skrip mengeksekusi perintah berikut terhadap berkas target:
   ```bash
   strings -a -t x "$1" > "$1.ltdis.strings.txt"
   objdump -Dj .text "$1" > "$1.ltdis.x86_64.txt"
   ```
2. **Eksekusi Analisis Statis via `ltdis.sh`:**
   Jalankan skrip terhadap biner `static`:
   ```bash
   chmod +x ltdis.sh
   ./ltdis.sh static
   ```
   Skrip menghasilkan dua berkas keluaran: `static.ltdis.strings.txt` dan `static.ltdis.x86_64.txt`.
3. **Pencarian Pola Flag pada Hasil Carving:**
   Gunakan utilitas pencarian pola `grep` untuk menelusuri format flag platform CyLab:
   ```bash
   grep "academy{" static.ltdis.strings.txt
   ```
   Output langsung mengembalikan token flag:
   ```text
      1020 academy{d15a5m_t34s3r_fac3431a}
   ```
4. **Metode Alternatif Langsung (One-Liner Carving):**
   Pemeriksaan dapat dilakukan secara langsung dalam satu baris perintah tanpa memerlukan skrip pembantu:
   ```bash
   strings static | grep "academy{"
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{d15a5m_t34s3r_fac3431a}`
- **Verifikasi API:** Validasi token pada endpoint `POST /api/submissions/` mengembalikan `{"correct": true, "challenge": 163}` (Status HTTP 201 Created).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Inspeksi Artefak Statis (LKS Forensic & Binary Module):** Dalam kompetisi LKS Cyber Security bidang Reverse Engineering dan Forensik, langkah pertama sebelum melakukan debugging dinamis (*dynamic analysis*) atau membuka decompiler berat (Ghidra/IDA) adalah melakukan identifikasi tipe berkas (`file`) dan ekstraksi string statis (`strings`).
- **Remediasi & Hardening Perangkat Lunak (NIST SP 800-64):**
  - Jangan pernah menyematkan data sensitif, kunci API, URL tersembunyi, atau kredensial autentikasi langsung di dalam kode sumber biner (*hardcoded secrets*).
  - Terapkan teknik compile-time string encryption (seperti macros template metaprogramming pada C++ atau obfuscator LLVM) jika konstanta biner harus dilindungi dari pembacaan langsung di ruang disk.

---

## Solver

Skrip solver mandiri tersedia pada `scripts/solve_163_static_aint_always_noise.py` yang mengotomatisasi pengambilan aset dan pembacaan pola string secara terisolasi.
