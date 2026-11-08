# Writeup: Hidden Cipher 1 (Challenge ID: 745)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / UPX De-obfuscation & Repeating-Key XOR Inversion (NIST SP 800-115 §4.3)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** Yahya Meddy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{xor_unpack_4nalys1s_f3d3a874}`
- **Flag Komunitas:** `CTF{xor_unpack_4nalys1s_f3d3a874}`
- **Standar Referensi:** NIST SP 800-115 Section 4.3 (Application Security & Binary Analysis), CWE-798 (Use of Hard-coded Credentials / Cryptographic Keys), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-326 (Inadequate Encryption Strength), & OWASP Testing Guide (Reverse Engineering Binaries).

---

## Problem Statement & Scope
Peserta diberikan berkas arsip `hiddencipher.zip` yang berisi biner eksekutabel ELF x86-64 `hiddencipher` dan berkas placeholder `flag.txt` lokal (`academy{fake_flag}`). 
Pada sistem live on-demand (`nc chatelaine.cylabacademy.net <port>`), layanan server mengeksekusi biner terhadap berkas flag rahasia yang sebenarnya dan memancarkan string *ciphertext* heksadesimal ke terminal pengguna.
Tujuan dari audit ini adalah melakukan analisis rekayasa balik (*reverse engineering*) terhadap mekanisme enkripsi yang diterapkan pada biner, mengekstrak parameter rahasia yang disematkan (*embedded secrets*), dan merekonstruksi teks terang bendera (*plaintext flag*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Kompresi Runtime UPX vs Proteksi Kriptografis
Pemeriksaan awal terhadap biner `hiddencipher` menggunakan utilitas `file` dan `readelf` menunjukkan bahwa biner dipadatkan menggunakan UPX (*Ultimate Packer for eXecutables*). 
UPX adalah utilitas kompresi biner untuk menghemat ukuran penyimpanan di disk, bukan alat enkripsi (*crypter*) yang memberikan keamanan data. Header segmen UPX (`UPX0`, `UPX1`, `UPX!`) dapat diuraikan kembali ke bentuk ELF aslinya menggunakan perintah `upx -d` secara instan, mengembalikan ukuran biner dari 7.056 byte menjadi 16.496 byte dengan seluruh seksi simbol dan instruksi assembly yang utuh.

### 2. Kunci Kriptografi Tertanam / Hard-coded Key (CWE-798)
Setelah biner diekstrak (*unpacked*), pembongkaran kode mesin (*disassembly*) pada fungsi `get_secret` mengungkap penyimpanan konstanta byte langsung ke segmen data:
```assembly
mov byte ptr [rbp-0x6], 0x53    ; ASCII 'S'
mov byte ptr [rbp-0x5], 0x33    ; ASCII '3'
mov byte ptr [rbp-0x4], 0x43    ; ASCII 'C'
mov byte ptr [rbp-0x3], 0x72    ; ASCII 'r'
mov byte ptr [rbp-0x2], 0x33    ; ASCII '3'
mov byte ptr [rbp-0x1], 0x74    ; ASCII 't'
```
Rangkaian byte tersebut membentuk string kunci simetris sepanjang 6 karakter: `S3Cr3t`. Menyematkan kunci rahasia langsung di dalam instruksi biner yang didistribusikan melanggar prinsip dasar keamanan Kerckhoffs (*Kerckhoffs's Principle*) dan diklasifikasikan sebagai kelemahan kritis CWE-798.

### 3. Kelemahan Kriptografi Simetris XOR (CWE-327 & CWE-326)
Fungsi `main` membaca berkas `flag.txt` ke dalam buffer memori, lalu melakukan enkripsi aliran byte (*stream cipher*) menggunakan operasi bitwise XOR terhadap kunci berulang:
$$C[i] = P[i] \oplus K[i \pmod 6]$$
Pada tingkat assembly x86-64, operasi modulo terhadap konstanta 6 dioptimasi oleh kompilator menjadi perkalian invers (magic number `0x2aaaaaab` untuk pembagian unsigned 32-bit):
```assembly
mov    eax, dword ptr [rbp-0x14]  ; index i
imul   rax, rax, 0x2aaaaaab      ; magic multiplication for division by 6
shr    rax, 0x20                  ; quotient i / 6
imul   eax, eax, 0x6              ; (i / 6) * 6
sub    edx, eax                   ; i - ((i / 6) * 6) = i % 6
```
Karena operasi bitwise XOR bersifat involusi (*self-inverse*):
$$(P \oplus K) \oplus K = P \oplus (K \oplus K) = P \oplus 0 = P$$
maka fungsi dekripsi identik dengan fungsi enkripsi. Siapa pun yang memiliki *ciphertext* dan kunci $K$ dapat langsung memulihkan teks asli $P$ tanpa memerlukan komputasi rumit atau brute-force.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Unpacking Biner UPX
Menggunakan utilitas UPX pada sistem Linux:
```bash
upx -d hiddencipher -o hiddencipher_unpacked
```
Biner berhasil didekompresi dari format terkompresi ke ELF 64-bit LSB pie executable x86-64 standar.

### Langkah 2: Audit Disassembly & Rekonstruksi Kunci
Menganalisis tabel fungsi dengan `objdump -d -M intel hiddencipher_unpacked`:
1. Menemukan fungsi `get_secret` pada offset `0x12a9`.
2. Mengekstrak 6 nilai byte: `[0x53, 0x33, 0x43, 0x72, 0x33, 0x74]`.
3. Mengonversi ke representasi ASCII: `S3Cr3t`.

### Langkah 3: Intersepsi Ciphertext dari Lab Remote
Membuka koneksi ke lab instance interaktif:
```bash
nc chatelaine.cylabacademy.net 22038
```
Layanan merespons dengan memancarkan string heksadesimal:
`3250221656192a483b1d412b265d3313501f0c072d135f0d2002302d55473700224a04402e`

### Langkah 4: Pemulihan Plaintext Flag via Inversi XOR
Menggunakan modul dekripsi Python:
$$\text{byte}_0 = 0x32 \oplus 0x53 = 0x61 \rightarrow \text{'a'}$$
$$\text{byte}_1 = 0x50 \oplus 0x33 = 0x63 \rightarrow \text{'c'}$$
$$\text{byte}_2 = 0x22 \oplus 0x43 = 0x61 \rightarrow \text{'a'}$$
$$\text{byte}_3 = 0x16 \oplus 0x72 = 0x64 \rightarrow \text{'d'}$$
$$\text{byte}_4 = 0x56 \oplus 0x33 = 0x65 \rightarrow \text{'e'}$$
$$\text{byte}_5 = 0x19 \oplus 0x74 = 0x6d \rightarrow \text{'m'}$$
$$\text{byte}_6 = 0x2a \oplus 0x53 = 0x79 \rightarrow \text{'y'}$$
...
Meneruskan operasi ini ke seluruh 37 byte menghasilkan string:
`academy{xor_unpack_4nalys1s_f3d3a874}`.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{xor_unpack_4nalys1s_f3d3a874}`
- **Flag Format Komunitas:** `CTF{xor_unpack_4nalys1s_f3d3a874}`
- **Verifikasi Live REST API CyLab:**
  Submisi ke `https://learn.cylabacademy.org/api/submissions/` mengembalikan respons status HTTP 201:
  `{"user": 1072359, "challenge": 745, "flag": "academy{xor_unpack_4nalys1s_f3d3a874}", "correct": true, "historical": false}`.
- **Verifikasi Skrip Mandiri:** Skrip reproduktif `scripts/solve_745_hidden_cipher_1.py` memvalidasi logika `HiddenCipherSimulator` dan mengonfirmasi dekripsi teks secara akurat.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Larangan Penggunaan Kunci Statis Tertanam (Hard-Coded Secrets)
Jangan pernah menyematkan kunci enkripsi simetris, token API, atau kredensial autentikasi langsung ke dalam kode sumber aplikasi atau artefak biner yang dikompilasi.
**Remediasi:**
Gunakan sistem manajemen rahasia terpusat (*Key Management Service* seperti AWS KMS, HashiCorp Vault, atau Linux Kernel Keyring) dengan autentikasi berbasis entitas dan pertukaran kunci dinamis (*ephemeral session keys*).

### 2. Migrasi ke Standar Kriptografi Terotentikasi (AEAD)
Operasi XOR dengan kunci berulang pendek rentan terhadap analisis frekuensi, serangan *known-plaintext*, dan pemulihan kunci instan.
**Remediasi:**
Gunakan algoritma enkripsi modern yang menyediakan kerahasiaan sekaligus integritas data (*Authenticated Encryption with Associated Data*), seperti **AES-256-GCM** atau **ChaCha20-Poly1305**, dengan Nonce acak unik per pesan enkripsi.

### 3. Pemahaman Proteksi Kompresi vs Obfuscation
UPX hanya bertindak sebagai utilitas pengurang ukuran biner (*binary compressor*), bukan mekanisme proteksi integritas. Di lingkungan kompetisi LKS Cyber Security bidang *Reverse Engineering*, mengenali signature packer standar (UPX, PECompact, ASPack) memungkinkan analis melakukan *stripping* dan *unpacking* cepat guna mengakses logika fungsional biner yang sebenarnya.
