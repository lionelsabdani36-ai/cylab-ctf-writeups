# Writeup: Keygenme (Challenge ID: 276)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Static Keygen Construction & MD5 Digest Carving (CWE-208 / CWE-312)
- **Difficulty:** Hard (diff=3)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 400
- **Flag:** `academy{br1ng_y0ur_0wn_k3y_5b5d983e}`

---

## Problem Statement & Scope

Tantangan menyajikan sebuah berkas biner ELF 64-bit Linux x86-64 unstripped bernama `keygenme`:
> *"Can you get the flag? Reverse engineer this binary."*

Spesifikasi lingkungan:
- Format berkas: ELF 64-bit LSB executable, x86-64, dynamically linked dengan OpenSSL `libcrypto.so.1.1`, not stripped.
- Program meminta pengguna memasukkan lisensi aktivasi produk (*license key*) melalui antarmuka konsol standar (`stdin`).
- Jika lisensi yang dimasukkan valid, program merespons dengan konfirmasi `That key is valid.`.
- Peserta ditantang merekonstruksi algoritma verifikasi kunci dan membangun generator lisensi (*keygen*) reproduktif untuk memulihkan flag resmi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Pemeriksaan Batas Panjang Kunci Statis:**
   - Pada fungsi `main` (alamat offset `0x149b`), program membaca input lisensi menggunakan `fgets(buf, 0x25, stdin)`.
   - Pada fungsi validasi `check_key` (offset `0x1209`), panjang string divalidasi secara ketat terhadap nilai `0x24` (36 desimal) via instruksi `cmp rax, 0x24`. Kunci dengan panjang selain 36 karakter langsung ditolak.
2. **Rekonstruksi Komponen Kunci (Dynamic Key Assembly):**
   Fungsi validasi menyusun kunci target ke dalam buffer stack `[rbp-0x30]` melalui tahapan deterministik:
   - Tahap 1: Menyalin prefix sepanjang 27 karakter dari konstanta statis stack: `academy{br1ng_y0ur_0wn_k3y_` (indeks 0 hingga 26).
   - Tahap 2: Menghitung hash kriptografis MD5 dari prefix dan suffix (`}`):
     - `hex_1 = MD5("academy{br1ng_y0ur_0wn_k3y_").hexdigest()` -> `716d14648eaf13021431eb50f77dd070`
     - `hex_2 = MD5("}").hexdigest()` -> `cbb184dd8e05c9709e5dcaedaa0495cf`
   - Tahap 3: Mengambil 8 karakter dinamis dari digest MD5 berdasarkan indeks offset stack:
     - `hex_1[22]` = `'5'`
     - `hex_1[21]` = `'b'`
     - `hex_1[22]` = `'5'`
     - `hex_1[3]`  = `'d'`
     - `hex_2[13]` = `'9'`
     - `hex_1[8]`  = `'8'`
     - `hex_1[13]` = `'3'`
     - `hex_1[9]`  = `'e'`
   - Tahap 4: Menutup kunci dengan karakter delimiter akhir `}`.
3. **Komparasi Byte-per-Byte (CWE-208 / NIST SP 800-115 § 4.3):**
   Loop verifikasi membandingkan setiap karakter input pengguna dengan buffer target dari indeks 0 hingga 35 (`0x23`). Karena seluruh masukan algoritma bersifat deterministik dan komponen kunci dapat dihitung secara statis tanpa rahasia server, pembuatan keygen otomatis (*reproducible key generator*) dapat dibangun dengan presisi 100%.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Disassembly ELF:**
   Melakukan inspeksi terhadap biner menggunakan `objdump -M intel -d keygenme` untuk memetakan alur pemanggilan fungsi `main` dan fungsi verifikasi `check_key` pada `0x1209`.
2. **Pemetaan Variabel Stack Frame:**
   Mengidentifikasi bahwa fungsi menggunakan library OpenSSL `MD5@plt` dan `sprintf@plt` dengan format string `%02x` guna mengonversi digest biner menjadi representasi string heksadesimal lowercase.
3. **Ekstraksi Indeks Karakter Dinamis:**
   Menganalisis instruksi `movzx eax, BYTE PTR [rbp - offset]` sebelum pengisian buffer `[rbp-0x15]` hingga `[rbp-0xd]`.
4. **Implementasi Key Generator:**
   Menghitung hash MD5 secara independen menggunakan modul `hashlib` Python dan menggabungkan karakter yang sesuai untuk menghasilkan kunci lisensi penuh.
5. **Verifikasi Terhadap Biner Target:**
   Mengirimkan string `academy{br1ng_y0ur_0wn_k3y_5b5d983e}` ke program biner melalui stdin:
   `echo "academy{br1ng_y0ur_0wn_k3y_5b5d983e}" | ./keygenme`
   Biner mengonfirmasi keberhasilan dengan output `That key is valid.`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{br1ng_y0ur_0wn_k3y_5b5d983e}`
- **Status Live Solver:** Terverifikasi live HTTP 201 (`correct: true`) pada platform CyLab Security Academy via `scripts/solve_276_keygenme.py`.
- **Hasil Pengujian Biner:** Program biner `/tmp/keygenme` merespons dengan konfirmasi `That key is valid.`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Kriptografi Asimetris untuk Lisensi Produk (Public-Key Licensing):**
   Skema lisensi software tidak boleh mengandalkan algoritma simetris statis atau hash satu arah (MD5/SHA) yang diverifikasi di sisi klien. Verifikasi lisensi modern harus menggunakan verifikasi tanda tangan digital asimetris (seperti RSA-PSS atau Ed25519), di mana biner hanya menyimpan kunci publik (*public key*) untuk memverifikasi lisensi yang ditandatangani oleh kunci privat (*private key*) vendor.
2. **Depresiasi Algoritma MD5 (NIST SP 800-131A):**
   Algoritma MD5 memiliki kerentanan tabrakan (*collision attack*) yang signifikan dan dilarang digunakan dalam konteks integritas atau autentikasi data modern sesuai standar FIPS 140-3 / NIST SP 800-131A. Gunakan minimal keluarga SHA-2 (SHA-256) atau SHA-3 / BLAKE3.
3. **Relevansi Modul LKS:**
   Tantangan ini mencakup kompetensi inti Reverse Engineering LKS Cyber Security Nasional: rekonstruksi algoritma keygen dari biner ELF terkompilasi, analisis pemetaan stack frame dan calling convention x86-64, serta implementasi otomasi solver bahasa pemrograman tingkat tinggi.
