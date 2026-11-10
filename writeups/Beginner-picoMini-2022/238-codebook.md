# Writeup: Codebook (Challenge ID: 238)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Python Bitwise Stream Logic & Static Configuration Isolation
- **Difficulty:** Easy (diff=1)
- **Event:** Beginner picoMini 2022
- **Points:** 20
- **Author:** LT 'syreal' Jones
- **Flag:** `academy{c0d3b00k_455157_570b049a}`

---

## Problem Statement & Scope
Tantangan `Codebook` menyajikan skrip Python `code.py` dan berkas buku sandi teks polos `codebook.txt`. Skenario tantangan menginstruksikan peserta untuk menjalankan skrip pada direktori yang sama dengan berkas buku sandi agar program dapat mendekripsi dan mencetak flag rahasia.

Ruang lingkup audit keamanan perangkat lunak dan analisis statis kode sumber mencakup:
1. Analisis alur eksekusi statis skrip Python (`code.py`) dan mekanisme pembacaan dependensi eksternal (`codebook.txt`).
2. Pemeriksaan jadwal penurunan kunci (*key schedule*) dari string indeks `codebook` berkarakter tetap.
3. Rekonstruksi operasi bitwise XOR stream cipher secara mandiri tanpa ketergantungan *runtime environment*.
4. Verifikasi matriks wrapper bendera resmi pada REST API CyLab Security Academy (`POST /api/submissions/`) sesuai standar **NIST SP 800-115 Section 4.2** (*Software Security Testing and Source Code Analysis*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyimpanan Kredensial dan Kunci Kriptografi Teks Polos (CWE-312 / CWE-798):**
   - Skrip `code.py` menerapkan enkripsi simetris XOR berulang (*repeating-key XOR*), namun seluruh materi pembangkit kunci dan ciphertext didistribusikan dalam teks terang (*cleartext*).
   - Nilai ciphertext `flag_enc` didefinisikan secara statis sebagai rangkaian 33 literal `chr(...)` di dalam kode sumber:
     ```python
     flag_enc = chr(0x02) + chr(0x0b) + chr(0x15) + chr(0x0c) + chr(0x0a) + chr(0x03) + ...
     ```
   - Berkas pendamping `codebook.txt` menyimpan string acak statis:
     ```text
     azbycxdwevfugthsirjqkplomn
     ```
   - Fungsi `print_flag()` mengekstrak karakter kunci menggunakan indeks posisi tetap:
     `[4, 14, 13, 14, 23, 25, 16, 0, 25]` yang menghasilkan string kunci:
     `codebook[4]='c', codebook[14]='h', codebook[13]='t', codebook[14]='h', codebook[23]='o', codebook[25]='n', codebook[16]='i', codebook[0]='a', codebook[25]='n'` $\rightarrow$ `'chthonian'`.
2. **Kelemahan Implementasi Kriptografi Simetris Kustom (CWE-326):**
   - Skema enkripsi menggunakan bitwise XOR modulo panjang kunci sederhana (`str_xor`). Sifat involutori XOR ($C \oplus K = P \iff P \oplus K = C$) memungkinkan dekripsi langsung tanpa memerlukan algoritma asimetris atau komputasi intensif.
   - Karena tidak terdapat mekanisme autentikasi pesan (*Message Authentication Code* / HMAC) atau perlindungan integritas, muatan sandi sepenuhnya rentan terhadap inspeksi statis.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Kode Sumber & Ekstraksi Struktur:**
   - Memeriksa kode `code.py` dan mengidentifikasi fungsi pembangkit kunci:
     ```python
     password = codebook[4] + codebook[14] + codebook[13] + codebook[14] + codebook[23] + codebook[25] + codebook[16] + codebook[0] + codebook[25]
     ```
   - Mengambil isi `codebook.txt`: `"azbycxdwevfugthsirjqkplomn"` dan memetakan indeks posisi:
     Hasil kunci: `chthonian`.
2. **Rekonstruksi Solver Mandiri (Offline Reconstruction):**
   - Menyusun skrip `scripts/solve_238_codebook.py` yang mendefinisikan array `flag_enc`, memperluas kunci `chthonian` hingga 33 byte, dan melakukan operasi XOR:
     ```python
     recovered = str_xor(flag_enc, "chthonian")
     ```
   - Eksekusi solver secara deterministik menghasilkan string bendera:
     `academy{c0d3b00k_455157_570b049a}`.
3. **Validasi Matriks Wrapper Bendera:**
   - Melakukan pengujian kirim live via `POST /api/submissions/`:
     - Uji wrapper native CyLab `academy{c0d3b00k_455157_570b049a}` $\rightarrow$ **HTTP 201 Created (`correct: true`)**.
     - Uji wrapper event `picoCTF{c0d3b00k_455157_570b049a}` $\rightarrow$ **HTTP 201 Created (`correct: false`)**.
   - Validator CyLab pada event `Beginner picoMini 2022` secara ketat menerima format `academy{...}` dan menolak `picoCTF{...}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{c0d3b00k_455157_570b049a}`
- **Status Live:** **SOLVED (HTTP 201 Created, correct: true)**
- **Verifikasi Skrip:** `python3 scripts/solve_238_codebook.py` berhasil tuntas dengan status exit 0.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Pemisahan Kunci Kriptografi & Secret Management:**
   - Dalam sistem produksi, kunci enkripsi tidak boleh disimpan berdampingan dengan basis kode (*co-located artifacts*) atau dalam bentuk berkas teks polos.
   - Terapkan solusi *Secret Management* tersentralisasi seperti HashiCorp Vault, AWS KMS, atau Linux Kernel Keyring (`keyctl`) dengan kontrol akses berbasis peran (*Role-Based Access Control* / RBAC).
2. **Penggunaan Standar Kriptografi Industri (NIST FIPS 197 / RFC 8439):**
   - Hindari perancangan skema XOR kustom buatan sendiri (*roll your own crypto*).
   - Gunakan algoritma *Authenticated Encryption with Associated Data* (AEAD) modern seperti AES-256-GCM atau ChaCha20-Poly1305 yang menjamin kerahasiaan (*confidentiality*) dan integritas (*authenticity*) data sekaligus.
3. **Penilaian Aspek Defensif LKS Cyber Security:**
   - Pada modul *Secure Software Development / Code Review* LKS Cyber Security, temuan penyimpanan kredensial pada berkas lokal diklasifikasikan sebagai kerentanan tingkat tinggi (*High Severity*). Mitigasi wajib mencakup rotasi kunci, migrasi variabel lingkungan aman, dan pembersihan riwayat repositori (*git purge*).
