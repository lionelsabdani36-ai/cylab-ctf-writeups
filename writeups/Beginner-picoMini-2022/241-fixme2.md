# Writeup: fixme2.py (Challenge ID: 241)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Python Syntax & Operator Equality Remediation
- **Difficulty:** Easy (diff=1)
- **Event:** Beginner picoMini 2022
- **Playlist:** Python in CTF's (Module 110)
- **Points:** 25
- **Author:** LT 'syreal' Jones
- **Flag:** `academy{3qu4l1ty_n0t_4551gnm3nt_ad29eab9}`

---

## Problem Statement & Scope
Tantangan `fixme2.py` menyajikan sebuah skrip otomasi Python yang mengalami kegagalan kompilasi dan eksekusi akibat kesalahan sintaksis operator (*syntax error*). Peserta ditugaskan untuk melakukan audit statis terhadap kode sumber, mendeteksi baris kode yang memicu kegagalan parsing pada interpreter, melakukan remediasi sintaksis berbasis spesifikasi tata bahasa Python, dan mengekstrak token bendera resmi.

Ruang lingkup audit keamanan perangkat lunak dan analisis statis kode sumber mencakup:
1. Analisis pohon sintaks abstrak (*Abstract Syntax Tree* / AST) dan aturan tata bahasa Python mengenai pembedaan operator penugasan (*assignment*) dan perbandingan (*equality*) sesuai PEP 8 dan Python Language Reference Section 6.10 & 7.2.
2. Remediasi kesalahan operator tanpa mendegradasi integritas algoritma dekripsi stream XOR yang tertanam.
3. Rekonstruksi algoritma dekripsi stream XOR mandiri (*offline solver*) dan evaluasi deterministik token.
4. Verifikasi matriks wrapper bendera resmi pada REST API CyLab Security Academy (`POST /api/submissions/`) sesuai standar **NIST SP 800-115 Section 4.2** (*Software Security Testing and Source Code Analysis*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kebingungan Semantik Operator Penugasan vs Perbandingan (CWE-480 / CWE-398):**
   - Dalam tata bahasa formal bahasa Python, simbol `=` merupakan operator pernyataan penugasan (*assignment statement*). Berbeda dengan bahasa turunan C yang memungkinkan penugasan menghasilkan nilai ekspresi di dalam ekspresi kondisional (kecuali operator *walrus* `:=` pada Python 3.8+ yang memerlukan sintaksis eksplisit), tata bahasa Python melarang penggunaan operator penugasan langsung `=` di dalam klausa `if condition:`.
   - Pada `fixme2.py`, baris 22 mendefinisikan blok evaluasi:
     ```python
     # Check that flag is not empty
     if flag = "":
       print('String XOR encountered a problem, quitting.')
     else:
       print('That is correct! Here\'s your flag: ' + flag)
     ```
     Parser menghasilkan galat fatal saat fase kompilasi bytecode:
     `SyntaxError: invalid syntax. Maybe you meant '==' or ':=' instead of '='?`.
   - Mengganti operator penugasan `=` dengan operator perbandingan nilai (*equality operator*) `==` memulihkan integritas AST sehingga skrip dapat dieksekusi secara mulus.
2. **Kelemahan Isolasi Kunci Kriptografis dan Data Rahasia (CWE-312 / CWE-798):**
   - Ciphertext `flag_enc` disimpan sebagai rangkaian 41 karakter literal `chr(...)` di dalam skrip:
     ```python
     flag_enc = chr(0x04) + chr(0x0d) + chr(0x0a) + chr(0x0d) + ...
     ```
   - Kunci enkripsi `'enkidu'` tertanam langsung dalam teks polos (*hardcoded cleartext credential*).
   - Mekanisme proteksi hanya bertumpu pada kegagalan eksekusi skrip akibat kesalahan sintaksis sepele, bukan pada perlindungan kriptografis atau kontrol otorisasi yang aman (*security through obscurity failure*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pemeriksaan Diagnostik Kode Sumber:**
   - Menjalankan `python3 fixme2.py` memicu pelacakan kesalahan kompilasi:
     ```text
       File "fixme2.py", line 22
         if flag = "":
                 ^
     SyntaxError: invalid syntax. Maybe you meant '==' or ':=' instead of '='?
     ```
2. **Remediasi Sintaksis AST:**
   - Mengubah baris 22 dari `if flag = "":` menjadi `if flag == "":`:
     ```python
     if flag == "":
       print('String XOR encountered a problem, quitting.')
     else:
       print('That is correct! Here\'s your flag: ' + flag)
     ```
3. **Rekonstruksi Solver Mandiri (Offline Solver):**
   - Membangun skrip reproduksi mandiri `scripts/solve_241_fixme2.py` yang mendefinisikan array `FLAG_ENC` (41 byte), kunci `'enkidu'`, dan fungsi dekripsi repeating-key stream XOR:
     ```python
     def str_xor(secret: str, key: str) -> str:
         new_key = key
         i = 0
         while len(new_key) < len(secret):
             new_key = new_key + key[i]
             i = (i + 1) % len(key)
         return "".join([chr(ord(sc) ^ ord(kc)) for sc, kc in zip(secret, new_key)])
     ```
   - Eksekusi solver secara deterministik memulihkan string bendera resmi:
     `academy{3qu4l1ty_n0t_4551gnm3nt_ad29eab9}`.
4. **Validasi Matriks Wrapper Bendera:**
   - Melakukan pengujian kirim live via `POST /api/submissions/`:
     - Uji wrapper native CyLab `academy{3qu4l1ty_n0t_4551gnm3nt_ad29eab9}`: **HTTP 201 Created (`correct: true`)**.
     - Uji wrapper event `picoCTF{3qu4l1ty_n0t_4551gnm3nt_ad29eab9}`: **HTTP 201 Created (`correct: false`)**.
   - Validator CyLab pada event `Beginner picoMini 2022` secara ketat menerima format `academy{...}` dan menolak `picoCTF{...}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{3qu4l1ty_n0t_4551gnm3nt_ad29eab9}`
- **Status Live:** **SOLVED (HTTP 201 Created, correct: true)**
- **Verifikasi Skrip:** `python3 scripts/solve_241_fixme2.py` berhasil tuntas dengan status exit 0.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Sintaksis dan Pengujian SAST Otomatis:**
   - Dalam kompetisi LKS Cyber Security bidang *Secure Programming*, peserta harus memiliki kepekaan tinggi dalam membaca pesan kesalahan parser interpreter dan mendeteksi kesalahan operator logika umum (`=` vs `==`, `&` vs `and`, `|` vs `or`).
   - Terapkan alat pemindaian statis (*linter* seperti `ruff`, `flake8`, atau `pylint`) dalam alur *Continuous Integration* untuk mengidentifikasi kesalahan sintaksis sebelum perangkat lunak dirilis.
2. **Prinsip Manajemen Rahasia Kriptografis (Secret Management):**
   - Jangan pernah menyematkan material kriptografis (kunci dekripsi atau ciphertext sensitif) secara langsung dalam kode sumber (*hardcoded secret* / CWE-798).
   - Gunakan solusi manajemen rahasia profesional (*Key Management Service* / KMS atau HashiCorp Vault) dan terapkan mekanisme enkripsi data terautentikasi (seperti AES-GCM atau ChaCha20-Poly1305) daripada cipher XOR sederhana buatan sendiri.
3. **Relevansi Modul LKS Cyber Security:**
   - Materi ini melatih ketelitian membaca kode pada modul *Incident Response & Source Code Audit*, di mana kode skrip berbahaya sering kali menyamarkan operasi jahat di balik kesalahan sintaksis yang disengaja.
