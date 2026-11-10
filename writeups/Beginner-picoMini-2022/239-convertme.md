# Writeup: convertme.py (Challenge ID: 239)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Radix Transformation & Static Flag Recovery
- **Difficulty:** Easy (diff=1)
- **Event:** Beginner picoMini 2022
- **Points:** 20
- **Author:** LT 'syreal' Jones
- **Flag:** `academy{4ll_y0ur_b4535_fff0af3d}`

---

## Problem Statement & Scope
Tantangan `convertme.py` menyajikan berkas skrip Python interaktif (`convertme.py`). Ketika dieksekusi, skrip memilih bilangan bulat berbasis desimal secara acak dalam rentang $[10, 100]$ dan menginstruksikan pengguna untuk mengonversi nilai tersebut ke format biner (*base-2*).

Apabila jawaban masukan pengguna cocok dengan hasil konversi, skrip mengeksekusi fungsi bitwise XOR untuk mendekripsi flag dan menampilkannya pada konsol terminal.

Ruang lingkup audit keamanan perangkat lunak dan analisis statis kode sumber mencakup:
1. Analisis representasi biner dan mekanisme konversi basis bilangan (*radix transformation: decimal to binary*).
2. Pemeriksaan logika validasi input klien (*client-side input verification gate*) versus pemaparan aset kriptografis statis.
3. Rekonstruksi algoritma dekripsi stream XOR mandiri tanpa eksekusi interaktif.
4. Verifikasi matriks wrapper bendera resmi pada REST API CyLab Security Academy (`POST /api/submissions/`) sesuai standar **NIST SP 800-115 Section 4.2** (*Software Security Testing and Source Code Analysis*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Konversi Basis Bilangan (Radix Transformation: Decimal to Binary):**
   - Sistem bilangan desimal menggunakan basis 10 (simbol 0–9), sedangkan biner menggunakan basis 2 (simbol 0 dan 1).
   - Konversi dari desimal ke biner dapat dilakukan dengan pembagian berulang oleh 2 dan mencatat sisa hasil bagi (*remainder*) dari bit bobot terkecil (*LSB*) hingga terbesar (*MSB*), atau menggunakan fungsi bawaan `bin(n)[2:]` pada Python.
   - Contoh representasi: Angka desimal 42 diurai menjadi:
     $$42 = 32 + 8 + 2 = 2^5 + 2^3 + 2^1 \implies 101010_2$$
2. **Ketergantungan Keamanan pada Pemeriksaan Sisi Klien (CWE-807 / CWE-312 / CWE-798):**
   - Logika program mengkondisikan rilis informasi sensitif pada keberhasilan evaluasi masukan pengguna:
     ```python
     if ans_num == num:
         flag = str_xor(flag_enc, 'enkidu')
     ```
   - Namun, ciphertext `flag_enc` (32 karakter `chr(...)`) dan kunci simetris `'enkidu'` didefinisikan secara statis di dalam berkas skrip yang didistribusikan kepada pengguna publik.
   - Pemeriksaan kondisi `ans_num == num` tidak memiliki kendali server otoritatif (*server-side gate*). Penganalisis dapat memanggil fungsi `str_xor(flag_enc, 'enkidu')` secara langsung atau mengekstrak token secara deterministik tanpa perlu menjalankan antarmuka input interaktif.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Statis & Ekstraksi Komponen Kriptografi:**
   - Membaca berkas `convertme.py` dan mengekstrak array ciphertext `flag_enc` dan kunci statis `'enkidu'`.
2. **Rekonstruksi Solver Mandiri (Offline Solver):**
   - Menyusun skrip `scripts/solve_239_convertme.py` yang mendefinisikan array `flag_enc`, mereplikasi fungsi `str_xor`, dan mengevaluasi dekripsi secara deterministik:
     ```python
     recovered = str_xor(FLAG_ENC, "enkidu")
     ```
   - Eksekusi solver menghasilkan string bendera:
     `academy{4ll_y0ur_b4535_fff0af3d}`.
3. **Validasi Matriks Wrapper Bendera:**
   - Melakukan pengujian kirim live via `POST /api/submissions/`:
     - Uji wrapper native CyLab `academy{4ll_y0ur_b4535_fff0af3d}` $\rightarrow$ **HTTP 201 Created (`correct: true`)**.
     - Uji wrapper event `picoCTF{4ll_y0ur_b4535_fff0af3d}` $\rightarrow$ **HTTP 201 Created (`correct: false`)**.
   - Validator CyLab pada event `Beginner picoMini 2022` secara ketat menerima format `academy{...}` dan menolak `picoCTF{...}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{4ll_y0ur_b4535_fff0af3d}`
- **Status Live:** **SOLVED (HTTP 201 Created, correct: true)**
- **Verifikasi Skrip:** `python3 scripts/solve_239_convertme.py` berhasil tuntas dengan status exit 0.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Pemisahan Logika Proteksi & Logika Presentasi (Client-Side Gate Elimination):**
   - Dalam perancangan perangkat lunak aman, otorisasi data sensitif tidak boleh bergantung pada pemeriksaan variabel sisi klien.
   - Logika evaluasi kuis/masukan harus diisolasi pada lingkungan server (*authoritative backend*), dan token sensitif hanya dikirimkan melalui saluran terenkripsi setelah validasi berhasil.
2. **Manajemen Rahasia & Enkripsi End-to-End:**
   - Jangan menyematkan kunci enkripsi (*hard-coded keys*) atau teks sandi kritis dalam kode sumber aplikasi klien.
   - Terapkan mekanisme autentikasi berbasis sesi aman dan pertukaran kunci dinamis (*ephemeral key exchange* seperti ECDH).
3. **Penilaian Aspek Defensif LKS Cyber Security:**
   - Pada modul *Secure Software Development / Code Review* LKS Cyber Security, kerentanan hard-coded cryptographic credentials dan client-side authorization bypass diklasifikasikan sebagai temuan kritis. Remediasi wajib mencakup arsitektur ulang otorisasi dan pembersihan seluruh materi kunci dari kode sumber.
