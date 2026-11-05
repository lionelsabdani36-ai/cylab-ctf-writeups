# Writeup: strings it (Challenge ID: 37)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Binary String Extraction & Static Analysis
- **Difficulty:** Easy (diff=1)
- **Author:** Sanjay C/Danny Tunitis
- **Event:** picoCTF 2019
- **Points:** 100
- **Flag:** `academy{5tRIng5_1T_b1e21039}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan analisis statis dasar pada artefak biner ELF tanpa mengeksekusi program (*static analysis without execution*):
> *"Can you find the flag in file without running it?"*

Lingkungan target menyediakan berkas biner eksekusi Linux berukuran ~783 KB bernama `strings`. Peserta diarahkan untuk menemukan artefak rahasia (*flag*) yang tertanam di dalam biner menggunakan perkakas analisis biner standar POSIX.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Biner ELF & Segmentasi Memori (`.rodata` / String Literals):**
   - Dalam format biner ELF (*Executable and Linkable Format*), string literal yang dikompilasi ke dalam kode sumber secara default dialokasikan pada seksi read-only data (`.rodata`) atau bagian segmen teks (`.text`).
   - String ASCII disimpan sebagai sekuens byte berurutan yang diakhiri karakter null (`\x00` / null-terminated string).
   - Selama proses kompilasi tanpa enkripsi data (*data obfuscation*), konstanta teks tetap berada dalam format plaintext murni di dalam berkas biner.

2. **Analisis Statis Kode Objek Sesuai Standar NIST SP 800-115:**
   - Standar NIST SP 800-115 (Section 5.3: *Object Code and Binary Analysis Techniques*) menegaskan prinsip keamanan penting: biner yang berasal dari sumber tidak tepercaya atau lingkungan investigasi tidak boleh dieksekusi secara sembarangan (*do not execute untrusted binaries blindly*).
   - Analisis statis teks biner melalui utilitas `strings` memindai berkas biner byte-per-byte untuk mencari deretan karakter ASCII/UTF-8 yang dapat dicetak (*printable characters*) dengan panjang minimum tertentu (default 4 karakter).
   - Pendekatan ini memungkinkan ekstraksi informasi kredensial, URL target, kunci kriptografi statis, dan flag tanpa memicu eksekusi kode berbahaya.

3. **Penyimpanan Informasi Sensitif Tanpa Proteksi (CWE-312):**
   - Masalah keamanan pada modul ini diklasifikasikan sebagai CWE-312 (*Cleartext Storage of Sensitive Information*). Nilai token rahasia ditanam secara langsung (*hardcoded*) ke dalam kode biner tanpa melalui proteksi kriptografi, deobfuskasi runtime, atau derivasi kunci dinamis.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan & Identifikasi Berkas Biner:**
   Unduh artefak biner dari repositori tantangan:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/dede17d717e026b75f6b9e7fb2c1601b46093ced6f209b8f6b27ffd883a9ae2f/strings
   ```
   Periksa tipe berkas menggunakan utilitas `file`:
   ```bash
   file strings
   ```
   Keluaran:
   ```text
   strings: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
   ```
   Berkas biner adalah ELF 64-bit yang belum di-*strip* (*not stripped*).

2. **Ekstraksi String Melalui Utilitas `strings`:**
   Jalankan utilitas `strings` dengan memfilter pola token target menggunakan `grep`:
   ```bash
   strings strings | grep -E "academy\{|picoCTF\{"
   ```
   Atau menggunakan flag pencarian awalan:
   ```bash
   strings strings | grep "academy{"
   ```
   Hasil ekstraksi langsung menampilkan flag utuh:
   ```text
   academy{5tRIng5_1T_b1e21039}
   ```

3. **Verifikasi Posisi Offset Biner (Hexdump):**
   Untuk memverifikasi letak offset penyimpanan flag dalam biner:
   ```bash
   grep -a -b -o "academy{[^}]*}" strings
   ```
   Keluaran menunjukkan posisi byte numerik tempat flag disimpan dalam bentuk byte ASCII plaintext.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{5tRIng5_1T_b1e21039}`
- **Verifikasi API Platform:** Validasi token melalui `POST /api/submissions/` menghasilkan respons sukses:
  ```json
  {"user": 1072359, "challenge": 37, "flag": "academy{5tRIng5_1T_b1e21039}", "correct": true, "historical": false}
  ```
  Status kode HTTP 201 Created mengonfirmasi keabsahan token.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Dalam kompetisi LKS bidang Cyber Security (modul *Reverse Engineering* dan *Forensics*), inspeksi string merupakan langkah triase awal (*first-pass reconnaissance*) wajib sebelum memasukkan biner ke dalam disassembler/dekompiler seperti Ghidra atau IDA Pro. Pemahaman mengenai seksi `.rodata` dan format literal membantu peserta dengan cepat membedakan data konfigurasi statis dari logika kontrol alur program.
- **Mitigasi Defensif (Secure Binary Build):**
  1. *Symbol Stripping:* Selalu terapkan proses stripping simbol (`strip -s` atau `-s` pada gcc) sebelum merilis berkas biner ke lingkungan produksi untuk menghapus informasi debugging dan tabel simbol non-esensial.
  2. *Sensitive Data Protection:* Jangan pernah menanam kredensial, token API, atau kunci privat secara hardcoded dalam biner.
  3. *Obfuscation / Dynamic Decryption:* Jika konstanta rahasia harus disimpan dalam biner (misal enkripsi aset aplikasi), terapkan enkripsi simetris (misal AES atau XOR dinamis) di mana kunci hanya didekripsi saat runtime dalam memori terlindungi (*secure enclaves*).

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_37_strings_it.py`.
