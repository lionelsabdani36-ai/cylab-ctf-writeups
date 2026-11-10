# Writeup: fixme1.py (Challenge ID: 240)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Python Syntax & AST Indentation Remediation
- **Difficulty:** Easy (diff=1)
- **Event:** Beginner picoMini 2022
- **Playlist:** Python in CTF's (Module 109)
- **Points:** 25
- **Author:** LT 'syreal' Jones
- **Flag:** `academy{1nd3nt1ty_cr1515_f63757ad}`

---

## Problem Statement & Scope
Tantangan `fixme1.py` menyajikan sebuah skrip Python yang mengalami kegagalan kompilasi akibat kesalahan sintaks tingkat tata bahasa (*syntax error*). Peserta diarahkan untuk mengidentifikasi baris yang memicu kesalahan, melakukan remediasi kode agar dapat diparsing oleh interpreter Python, dan mengeksekusi skrip untuk memperoleh token bendera resmi.

Ruang lingkup audit keamanan perangkat lunak dan analisis statis kode sumber mencakup:
1. Analisis pohon sintaks abstrak (*Abstract Syntax Tree* / AST) dan aturan tata bahasa Python terkait indentasi blok kode (PEP 8 / Python Language Reference §2.1.8).
2. Remediasi kesalahan tata bahasa tanpa mengubah logika kriptografis program.
3. Rekonstruksi algoritma dekripsi stream XOR mandiri dan ekstraksi token.
4. Verifikasi matriks wrapper bendera resmi pada REST API CyLab Security Academy (`POST /api/submissions/`) sesuai standar **NIST SP 800-115 Section 4.2** (*Software Security Testing and Source Code Analysis*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kesalahan Indentasi Tata Bahasa Python (PEP 8 / CWE-398):**
   - Berbeda dengan bahasa pemrograman turunan C yang menggunakan tanda kurung kurawal `{}` untuk mendefinisikan blok cakupan (*scope block*), Python menggunakan spasi indentasi (*whitespace indentation*) sebagai penanda struktural blok eksekusi (*suite*).
   - Pada `fixme1.py`, baris akhir program:
     ```python
     flag = str_xor(flag_enc, 'enkidu')
       print('That is correct! Here\'s your flag: ' + flag)
     ```
     memiliki spasi indentasi ekstra (2 karakter spasi) di depan pernyataan `print()`. Karena pernyataan ini tidak berada di dalam blok kontrol (`def`, `if`, `for`, `while`, `try`), parser lexer Python menghasilkan eksepsi fatal:
     `IndentationError: unexpected indent`.
2. **Ketergantungan Keamanan pada Integritas Kode Sumber Klien (CWE-312 / CWE-798):**
   - Ciphertext `flag_enc` disimpan sebagai rangkaian 34 literal `chr(...)` teks polos di dalam berkas skrip:
     ```python
     flag_enc = chr(0x04) + chr(0x0d) + chr(0x0a) + chr(0x0d) + chr(0x01) + chr(0x18) + ...
     ```
   - Kunci dekripsi `'enkidu'` didefinisikan sebagai string konstan tanpa perlindungan kriptografis tambahan.
   - Kegagalan program hanya disebabkan oleh galat sintaksis sepele, bukan oleh mekanisme proteksi akses data yang kuat (*security through obscurity failure*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pemeriksaan Diagnostik Sintaks:**
   - Menjalankan `python3 fixme1.py` menghasilkan pelacakan kesalahan:
     ```text
       File "fixme1.py", line 20
         print('That is correct! Here\'s your flag: ' + flag)
         ^
     IndentationError: unexpected indent
     ```
2. **Remediasi AST & Normalisasi Indentasi:**
   - Menghapus 2 karakter spasi di depan perintah `print()` sehingga sejajar pada kolom 0 (*root module scope*):
     ```python
     flag = str_xor(flag_enc, 'enkidu')
     print('That is correct! Here\'s your flag: ' + flag)
     ```
3. **Rekonstruksi Solver Mandiri (Offline Solver):**
   - Menyusun skrip `scripts/solve_240_fixme1.py` yang mendefinisikan array `flag_enc`, mereplikasi fungsi `str_xor`, dan mengevaluasi dekripsi secara deterministik:
     ```python
     recovered = str_xor(FLAG_ENC, "enkidu")
     ```
   - Eksekusi solver menghasilkan string bendera:
     `academy{1nd3nt1ty_cr1515_f63757ad}`.
4. **Validasi Matriks Wrapper Bendera:**
   - Melakukan pengujian kirim live via `POST /api/submissions/`:
     - Uji wrapper native CyLab `academy{1nd3nt1ty_cr1515_f63757ad}` $\rightarrow$ **HTTP 201 Created (`correct: true`)**.
     - Uji wrapper event `picoCTF{1nd3nt1ty_cr1515_f63757ad}` $\rightarrow$ **HTTP 201 Created (`correct: false`)**.
   - Validator CyLab pada event `Beginner picoMini 2022` secara ketat menerima format `academy{...}` dan menolak `picoCTF{...}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{1nd3nt1ty_cr1515_f63757ad}`
- **Status Live:** **SOLVED (HTTP 201 Created, correct: true)**
- **Verifikasi Skrip:** `python3 scripts/solve_240_fixme1.py` berhasil tuntas dengan status exit 0.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Integrasi Linting & Validasi Statis Otomatis (CI/CD Pipeline):**
   - Dalam pengembangan perangkat lunak modern, kesalahan sintaks dan indentasi harus dideteksi sebelum proses *commit* atau tahap *build* melalui integrasi perkakas *linter* dan *formatter* otomatis (seperti `ruff`, `flake8`, atau `black`).
   - Terapkan *pre-commit hooks* berbasis git untuk mencegah masuknya kode dengan inkonsistensi sintaks ke cabang utama (*mainline*).
2. **Penguatan Tata Kelola Kode Sumber:**
   - Pastikan lingkungan pengembangan menerapkan standar pemformatan yang seragam (misalnya konfigurasi editor `.editorconfig` dengan `indent_size = 4` dan `indent_style = space`).
3. **Penilaian Aspek Defensif LKS Cyber Security:**
   - Pada modul *Secure Programming & Static Application Security Testing (SAST)* di LKS Cyber Security, verifikasi sintaksis dan kepatuhan AST merupakan fondasi pengujian primer sebelum audit kelemahan logika bisnis atau celah injeksi memori.
