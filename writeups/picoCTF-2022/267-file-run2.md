# Writeup: file-run2 (Challenge ID: 267)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / CLI Argument Parsing & Static Binary Analysis
- **Difficulty:** Medium (diff=2)
- **Author:** Will Hong
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{F1r57_4rgum3n7_3819dbe5}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman penanganan argumen baris perintah (`argv` / `argc`) dan alur percabangan pada biner ELF Linux:
> *"Another program, but this time, it seems to want some input. What happens if you try to run it on the command line with input 'Hello!'? Download the program here."*

Peserta diberikan berkas biner Linux bernama `run` (16,080 bytes). Berbeda dengan modul pengenalan sebelumnya, biner ini menuntut input spesifik dari pengguna melalui argumen eksekusi untuk membuka alur kode pencetakan flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Mekanisme Passing Argumen POSIX (`argc` dan `argv`):**
   - Dalam konvensi pemanggilan fungsi `main(int argc, char **argv)` pada arsitektur x86-64:
     - `argc` menyimpan jumlah total token argumen (termasuk nama program pada `argv[0]`).
     - `argv` adalah array pointer menuju string karakter yang dialokasikan di atas stack oleh kernel sistem operasi saat pemanggilan `execve`.
   - Biner melakukan validasi:
     1. Apakah `argc == 2`? Jika tidak, mencetak pesan panduan: `"Run this file with only one argument."`.
     2. Membandingkan `argv[1]` dengan string konstan `"Hello!"` menggunakan `strcmp`.
     3. Jika cocok, mengeksekusi blok kode pencetakan flag rahasia.

2. **Penyimpanan Kredensial Statis (CWE-312 & CWE-798):**
   - Nilai token dan string perbandingan disimpan secara mentah di segmen teks/data biner tanpa teknik obfuskasi, enkripsi simetris, atau pemeriksaan integritas runtime.
   - Sesuai prinsip CWE-312 (Cleartext Storage of Sensitive Information) dan CWE-798 (Use of Hard-coded Credentials), logika otentikasi berbasis perbandingan string lokal rentan terhadap bypass melalui analisis statis instan.

3. **Metodologi Pengujian NIST SP 800-115:**
   - Standar NIST SP 800-115 merekomendasikan verifikasi alur kontrol program melalui kombinasi inspeksi statis simbol string dan observasi perilaku dinamis terhadap masukan tak tepercaya.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan & Identifikasi Berkas:**
   Unduh artefak biner dari repositori CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/ce5aa95ac9190d4d57106ecfcea8b60f5ef64535ddcbc052a561c922f2f19fbf/run
   ```
   Periksa izin dan jenis berkas:
   ```bash
   file run
   chmod +x ./run
   ```

2. **Observasi Respon Tanpa Argumen:**
   Jalankan program secara langsung:
   ```bash
   ./run
   ```
   Keluaran:
   ```text
   Run this file with only one argument.
   ```

3. **Eksekusi dengan Argumen yang Diminta:**
   Jalankan program dengan argumen string `"Hello!"`:
   ```bash
   ./run Hello!
   ```
   Keluaran:
   ```text
   The flag is: academy{F1r57_4rgum3n7_3819dbe5}
   ```

4. **Verifikasi Statis Alternatif (Strings Inspection):**
   Tanpa mengeksekusi program di lingkungan aktif, string flag dapat diekstrak langsung:
   ```bash
   strings run | grep -E "academy\{|picoCTF\{"
   ```
   Keluaran:
   ```text
   academy{F1r57_4rgum3n7_3819dbe5}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{F1r57_4rgum3n7_3819dbe5}`
- **Verifikasi API Platform:** Validasi token melalui `POST /api/submissions/` menghasilkan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 267, "flag": "academy{F1r57_4rgum3n7_3819dbe5}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Dalam skenario kompetisi LKS (Reverse Engineering & Binary Analysis), peserta harus mahir memetakan bagaimana input pengguna diteruskan ke fungsi komparasi (`strcmp`, `strncmp`, `memcmp`). Kemampuan membaca dekompilasi `main(argc, argv)` memungkinkan identifikasi parameter input yang tepat dalam hitungan detik.
- **Mitigasi Defensif (Input Validation & Secure Architecture):**
  1. *Sanitisasi dan Bound-Checking Argumen:* Selalu periksa panjang masukan `argv[1]` sebelum operasi pemrosesan memori untuk menghindari buffer overflow.
  2. *Server-Side Authorization:* Jangan pernah menggunakan perbandingan string lokal di biner klien sebagai penentu hak akses ke data bernilai tinggi.
  3. *Eliminasi Plaintext Constants:* Terapkan kompilasi dengan proteksi token dan teknik anti-tampering bila data rahasia wajib dimuat dalam biner.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_267_file_run2.py`.
