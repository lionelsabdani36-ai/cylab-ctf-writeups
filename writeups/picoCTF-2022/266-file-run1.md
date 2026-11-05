# Writeup: file-run1 (Challenge ID: 266)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Linux Binary Execution & Static Analysis
- **Difficulty:** Medium (diff=2)
- **Author:** Will Hong
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{U51N6_Y0Ur_F1r57_F113_4640f37e}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan eksekusi lingkungan command-line dan analisis biner ELF Linux:
> *"A program has been provided to you, what happens if you try to run it on the command line? Download the program here."*

Peserta diberikan tautan unduhan berkas eksekusi Linux berukuran 16 KB bernama `run`. Modul ini bertujuan mengenalkan interaksi biner tingkat sistem, pemberian hak akses eksekusi (`chmod +x`), dan pemahaman letak konstanta string di memori kode objek.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Biner ELF & Izin Eksekusi POSIX:**
   - Pada arsitektur Linux/POSIX, berkas yang baru diunduh melalui protokol jaringan (HTTP/HTTPS) secara default tidak memiliki bit izin eksekusi (`x`). Utilitas seperti `chmod +x` memanipulasi bit mask mode berkas (`st_mode`) pada struktur inode sistem berkas.
   - Panggilan biner dari direktori kerja saat ini memerlukan referensi jalur eksplisit (`./run`) karena direktori kerja saat ini (`.`) secara sengaja tidak dimasukkan ke dalam variabel lingkungan `$PATH` demi alasan keamanan sistem.

2. **Penyimpanan Informasi Sensitif Teks Terbuka (CWE-312 & CWE-798):**
   - Program biner mengompilasi string token rahasia secara langsung ke dalam segmen data baca-saja (`.rodata`).
   - Fungsi utama program (`main`) hanya memanggil fungsi `puts` atau `printf` dengan string literal yang telah tertanam. Hal ini melanggar prinsip CWE-312 (Cleartext Storage of Sensitive Information) dan CWE-798 (Use of Hard-coded Credentials), memungkinkan ekstraksi token baik melalui inspeksi statis maupun eksekusi dinamis langsung.

3. **Kepatuhan Metodologi NIST SP 800-115:**
   - Sesuai NIST SP 800-115 (Section 5.3: Object Code and Binary Analysis Techniques), inspeksi keamanan biner diawali dengan verifikasi tanda tangan format berkas (ELF Header `\x7fELF`), dilanjutkan inspeksi statis untuk meminimalkan risiko eksekusi kode berbahaya pada lingkungan tak terisolasi.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Akuisisi Berkas & Verifikasi Format:**
   Unduh artefak biner dari repositori CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/4cb47d716d0004f01f73bbcc894465736c68b3c2d78e32c622e5a63c2bcb885e/run
   ```
   Periksa tipe berkas menggunakan `file`:
   ```bash
   file run
   ```
   Keluaran:
   ```text
   run: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, not stripped
   ```

2. **Metode Statis (Strings Carving):**
   Pindai segmen string tanpa mengeksekusi biner:
   ```bash
   strings run | grep -E "academy\{|picoCTF\{"
   ```
   Keluaran:
   ```text
   academy{U51N6_Y0Ur_F1r57_F113_4640f37e}
   ```

3. **Metode Dinamis (CLI Invocation):**
   Beri hak akses eksekusi pada biner dan jalankan:
   ```bash
   chmod +x ./run
   ./run
   ```
   Keluaran:
   ```text
   The flag is: academy{U51N6_Y0Ur_F1r57_F113_4640f37e}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{U51N6_Y0Ur_F1r57_F113_4640f37e}`
- **Verifikasi API Platform:** Validasi token melalui `POST /api/submissions/` menghasilkan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 266, "flag": "academy{U51N6_Y0Ur_F1r57_F113_4640f37e}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Peserta kompetisi LKS wajib memahami hierarki izin sistem operasi Linux dan siklus hidup biner ELF. Membedakan kapan biner aman dieksekusi secara dinamis di sandbox versus dianalisis secara statis merupakan fondasi triase malware dan reverse engineering.
- **Mitigasi Defensif (Hardening & Credential Protection):**
  1. *Eliminasi Hardcoded Strings:* Jangan pernah menanam string rahasia, token akses, atau kunci privat di dalam kode sumber biner.
  2. *Secure Remote Retrieval:* Autentikasi dan verifikasi rahasia harus dilakukan di sisi server terlindungi melalui protokol terenkripsi (TLS 1.3) dan bukan melalui biner klien yang didistribusikan bebas.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_266_file_run1.py`.
