# Writeup: Secure Password Database (Challenge ID: 767)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Binary Exploitation (NIST SP 800-115 §4.2)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** Philip Thayer
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{d0nt_trust_us3rs}`
- **Flag Komunitas:** `CTF{d0nt_trust_us3rs}`

---

## Problem Statement & Scope

Tantangan menguji kemampuan peserta dalam analisis rekayasa balik biner ELF x86-64 serta eksploitasi celah manajemen memori pada alur otentikasi program:
> *"I made a new password authentication program that even shows you the password you entered saved in the database! Isn't that cool?"*

Layanan tantangan mendistribusikan berkas biner ELF 64-bit dinamis `system.out` (tidak ter-strip / *not stripped*). Biner bertindak sebagai aplikasi konsol yang mengizinkan pengguna menyimpan kata sandi ke dalam buffer dinamis heap, menampilkan byte memori yang tersimpan berdasarkan parameter panjang masukan pengguna, dan memverifikasi nilai hash rahasia sebelum mencetak isi berkas `flag.txt`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

Analisis statis dan dinamis pada berkas biner `system.out` mengungkap rantai kerentanan arsitektural multi-vektor:

1. **CWE-125 / Out-of-Bounds Heap Read (Heartbleed-Class Information Disclosure):**
   - Masukan awal kata sandi diterima melalui `fgets()` ke buffer stack berukuran `0x32` byte.
   - Program kemudian menyalin data tersebut menggunakan `strcpy()` ke area memori heap berukuran `0x5A` (90 byte) yang dialokasikan via `calloc(1, 0x5a)`.
   - Program selanjutnya meminta masukan panjang kata sandi (`length`) melalui `atoi()`.
   - Rutinitas pencetakan memori menjalankan iterasi `for (int i = 0; i < min(length, 0x5a); i++) printf("%d ", heap[i]);`.
   - Cacat fatal terjadi karena program mempercayai parameter `length` masukan pengguna tanpa membatasi iterasi pada panjang aktual string (`strlen()`). Saat pengguna memasukkan `length = 89`, program membaca dan membocorkan byte memori heap di luar batas masukan awal, termasuk artefak internal dan byte rahasia yang tersisa pada blok memori.

2. **CWE-328 / Reversible Weak Non-Cryptographic Hash Function:**
   - Mekanisme otentikasi menggunakan algoritma hashing non-kriptografis klasik `djb2` (uint64) dengan nilai awal *seed* `0x1505` (5381):
     $$h_{i} = ((h_{i-1} \ll 5) + h_{i-1} + c_i) \pmod{2^{64}}$$
   - Algoritma hashing ini tidak memiliki sifat ketahanan pre-image (*pre-image resistance*) atau anti-tabrakan (*collision resistance*), sehingga sangat rentan terhadap kalkulasi ulang langsung (*direct forward evaluation*).

3. **CWE-798 / Hard-Coded Obfuscated Secret in Read-Only Data (`.rodata`):**
   - Fungsi `make_secret()` menyalin rangkaian byte konstan `obf_bytes` dari seksi `.rodata` biner:
     `\xc3\xff\xc8\xc2\x92\x9b\x8b\xc0\x80\xc2\xc4\x8b\x00`
   - Setiap byte ditransformasi menggunakan operasi bitwise XOR terhadap konstanta `0xAA`:
     $$\text{Secret}[i] = \text{obf\_bytes}[i] \oplus \text{0xAA}$$
   - Dekode XOR menghasilkan string rahasia 12-byte: `iUbh81!j*hn!`.
   - Menghitung nilai hash `djb2(b"iUbh81!j*hn!")` menghasilkan integer deterministik:
     $$15237662580160011234$$
   - Karena algoritma, nilai secret ter-obfuskasi, dan kunci XOR tertanam secara statis di dalam biner, penyerang tidak memerlukan tebakan brute-force ataupun interaksi jaringan berulang; nilai hash otentikasi dapat dihitung secara instan secara matematis.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Statis & Ekstraksi Artefak Biner:**
   - Disassembly menggunakan `objdump -d -M intel system.out` untuk membedah alur fungsi `main`, `make_secret`, dan `hash`.
   - Membaca konstanta obfuskasi pada seksi `.rodata`:
     ```text
     obf_bytes: .byte 0xc3, 0xff, 0xc8, 0xc2, 0x92, 0x9b, 0x8b, 0xc0, 0x80, 0xc2, 0xc4, 0x8b
     ```
   - Operasi XOR dengan `0xAA`:
     - `0xc3 ^ 0xAA = 0x69` (`'i'`)
     - `0xff ^ 0xAA = 0x55` (`'U'`)
     - `0xc8 ^ 0xAA = 0x62` (`'b'`)
     - `0xc2 ^ 0xAA = 0x68` (`'h'`)
     - `0x92 ^ 0xAA = 0x38` (`'8'`)
     - `0x9b ^ 0xAA = 0x31` (`'1'`)
     - `0x8b ^ 0xAA = 0x21` (`'!'`)
     - `0xc0 ^ 0xAA = 0x6a` (`'j'`)
     - `0x80 ^ 0xAA = 0x2a` (`'*'`)
     - `0xc2 ^ 0xAA = 0x68` (`'h'`)
     - `0xc4 ^ 0xAA = 0x6e` (`'n'`)
     - `0x8b ^ 0xAA = 0x21` (`'!'`)
   - Teks rahasia yang dipulihkan: `iUbh81!j*hn!`.

2. **Kalkulasi Nilai Otentikasi DJB2:**
   - Implementasi algoritma DJB2 uint64 di Python:
     ```python
     h = 0x1505
     for c in b"iUbh81!j*hn!":
         h = ((h << 5) + h + c) & 0xFFFFFFFFFFFFFFFF
     # h == 15237662580160011234
     ```

3. **Otomasi Interaksi Layanan:**
   - Mengirimkan string dummy kata sandi: `A\n`
   - Memasukkan parameter panjang heap leak: `89\n`
   - Memasukkan nilai otentikasi hash yang dihitung: `15237662580160011234\n`
   - Layanan memverifikasi kesesuaian nilai hash dan mencetak flag.
   - Skrip reproduktif: `scripts/solve_767_secure_password_database.py`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{d0nt_trust_us3rs}`
- **Format Flag Komunitas:** `CTF{d0nt_trust_us3rs}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 767, "flag": "academy{d0nt_trust_us3rs}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Pencegahan Celah Pembacaan di Luar Batas (CWE-125 Remediation):**
   - Dalam kompetensi LKS Cyber Security bidang *Defensive Programming* dan *Binary Hardening*, aplikasi berbasis C/C++ tidak boleh mempercayai integer yang disediakan oleh pengguna sebagai batas loop pembacaan memori.
   - Gunakan fungsi verifikasi panjang aktual seperti `strnlen()` dan batasi pembacaan strictly pada `strlen(heap_buffer)` dengan pemeriksaan batas (*bound-checked wrappers*).
2. **Eliminasi Penggunaan Secret Statis (CWE-798 Hardening):**
   - Jangan pernah menyematkan token rahasia, passphrase, atau kunci enkripsi yang dapat direkayasa balik secara statis di dalam seksi teks atau `.rodata` biner.
   - Gunakan Key Management System (KMS), Hardware Security Module (HSM), atau injeksi variabel lingkungan runtime terproteksi.
3. **Penerapan Standar Hashing Password Kriptografis (NIST SP 800-63B / SP 800-115 §4.2):**
   - Hindari algoritma hash cepat/non-kriptografis (`djb2`, `MD5`, `SHA-1`) untuk otentikasi pengguna.
   - Wajibkan algoritma KDF yang diperkuat dengan salt acak berentropi tinggi serta faktor kerja memori/komputasi terukur (*memory-hard password hashing*), seperti Argon2id atau PBKDF2-HMAC-SHA256, dan lakukan komparasi waktu konstan (*constant-time comparison*) guna mencegah serangan saluran samping (*timing side-channel attacks*).
