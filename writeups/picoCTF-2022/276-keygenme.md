# 276 - Keygenme (Reverse Engineering, picoCTF 2022, Hard)

## Challenge Metadata
- ID: 276 | Event: picoCTF 2022 | Author: CyLab Academy
- Category: Reverse Engineering | Difficulty: Hard (3) | Points: 400
- Flag: `academy{br1ng_y0ur_0wn_k3y_5b5d983e}`

## Problem Statement & Scope
Tantangan menyajikan file biner ELF 64-bit Linux x86-64 bernama `keygenme`. Program meminta pengguna memasukkan lisensi aktivasi produk (license key) melalui antarmuka konsol standard input. Jika kunci yang dimasukkan valid, program merespons dengan pesan `That key is valid.`. Peserta ditantang untuk merekonstruksi logika validasi kunci dan menghasilkan keygen yang valid untuk mendapatkan flag kompetisi.

## Teori & Akar Kerentanan (Root Cause)
1. **Pemeriksaan Panjang Kunci Statis:**
   Pada fungsi `main` (alamat offset `0x149b`), program membaca input lisensi menggunakan `fgets(buf, 0x25, stdin)`. Pada fungsi validasi `check_key` (offset `0x1209`), panjang string divalidasi secara ketat terhadap nilai `0x24` (36 desimal) via `cmp rax, 0x24`. Kunci yang memiliki panjang selain 36 karakter langsung ditolak.
2. **Rekonstruksi Komponen Kunci (Dynamic Key Assembly):**
   Fungsi validasi menyusun kunci target ke dalam buffer stack `[rbp-0x30]` melalui tiga tahap:
   - Tahap 1: Menyalin prefix sepanjang 27 karakter dari konstanta statis stack:
     `academy{br1ng_y0ur_0wn_k3y_` (indeks 0 hingga 26).
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
   - Tahap 4: Menutup kunci dengan karakter penutup `}`.
3. **Komparasi Byte-per-Byte (CWE-208):**
   Loop verifikasi membandingkan setiap karakter input dengan buffer target dari indeks 0 hingga 35 (`0x23`). Karena seluruh input deterministik dan komponen kunci dapat dihitung statis, pembuatan keygen otomatis (reproducible key generator) dapat dibangun dengan presisi 100%.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Disassembly ELF:**
   Melakukan disassembler menggunakan `objdump -M intel -d keygenme` untuk menganalisis alur pemanggilan fungsi `main` dan fungsi verifikasi `0x1209`.
2. **Pemetaan Variabel Stack Frame:**
   Mengidentifikasi bahwa fungsi menggunakan library OpenSSL `MD5@plt` dan `sprintf@plt` dengan format string `%02x` untuk mengonversi digest biner menjadi hex lowercase.
3. **Ekstraksi Indeks Karakter Dinamis:**
   Menganalisis instruksi `movzx eax, BYTE PTR [rbp - offset]` sebelum pengisian buffer `[rbp-0x15]` hingga `[rbp-0xd]`.
4. **Implementasi Key Generator:**
   Menghitung hash MD5 secara independen menggunakan modul `hashlib` Python dan menggabungkan karakter yang sesuai untuk menghasilkan kunci lisensi penuh.
5. **Verifikasi Terhadap Biner Target:**
   Mengirimkan string `academy{br1ng_y0ur_0wn_k3y_5b5d983e}` ke program biner melalui stdin:
   `echo "academy{br1ng_y0ur_0wn_k3y_5b5d983e}" | ./keygenme`
   Biner mengonfirmasi keberhasilan dengan output `That key is valid.`.

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_276_keygenme.py`:
```python
import hashlib

prefix = b"academy{br1ng_y0ur_0wn_k3y_"
suffix = b"}"

h1 = hashlib.md5(prefix).hexdigest()
h2 = hashlib.md5(suffix).hexdigest()

key = (
    prefix.decode()
    + h1[22] + h1[21] + h1[22] + h1[3]
    + h2[13] + h1[8] + h1[13] + h1[9]
    + "}"
)
print("Generated Valid License Key:", key)
```

## Mitigasi Defensif & Relevansi LKS Cyber Security
1. **Kriptografi Asimetris untuk Lisensi Produk (Public-Key Licensing):**
   Skema lisensi software tidak boleh mengandalkan algoritma simetris statis atau hash satu arah (MD5/SHA) yang diverifikasi di sisi klien. Verifikasi lisensi modern harus menggunakan verifikasi tanda tangan digital asimetris (seperti RSA-PSS atau Ed25519), di mana biner hanya menyimpan public key untuk memverifikasi lisensi yang ditandatangani oleh private key vendor.
2. **Depresiasi Algoritma MD5:**
   MD5 memiliki kerentanan collision yang parah dan tidak boleh digunakan dalam konteks integritas atau autentikasi data modern (standar FIPS 140-3 / NIST SP 800-131A). Gunakan minimal SHA-256 atau BLAKE3.
3. **Relevansi Modul LKS:**
   Tantangan ini mencakup kompetensi inti Reverse Engineering LKS Cyber Security Nasional: rekonstruksi algoritma keygen dari biner ELF terkompilasi, analisis pemetaan stack frame dan calling convention x86-64, serta implementasi otomasi solver bahasa pemrograman tingkat tinggi.
