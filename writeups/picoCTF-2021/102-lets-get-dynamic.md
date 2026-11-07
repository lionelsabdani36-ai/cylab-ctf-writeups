# Writeup: Let's get dynamic (Challenge ID: 102)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Dynamic Stack Reconstruction & Array XOR Disassembly
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 300
- **Author:** Dylan McGuire
- **Flag:** `academy{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_0c8f18c}`

---

## Problem Statement & Scope
Tantangan `Let's get dynamic` menyajikan berkas kode rakitan GNU Assembler x86_64 (`chall.S`). Program membangun dua buah larik memori dinamis di dalam tumpukan lokal (*stack frame*) menggunakan instruksi pemuatan konstanta 64-bit langsung (*immediate quadwords* `movabs`), kemudian mengombinasikan elemen-elemen kedua larik tersebut melalui operasi XOR bertahap dengan indeks iterasi dan konstanta biner sebelum dicetak atau dibandingkan.

Peserta ditantang untuk menelusuri eksekusi rakitan x86_64 atau merekonstruksi nilai larik secara statis guna mengetahui string apa yang dibaca atau dibentuk oleh program.

Ruang lingkup audit keamanan perangkat lunak dan analisis rekayasa balik ini meliputi:
1. Analisis instruksi assembly arsitektur x86_64 dan struktur bingkai tumpukan (*stack frame layout* berbasis `rbp`).
2. Identifikasi pola obfuscation string memori berbasis *stack strings* dan pemuatan konstanta 64-bit (`movabs`).
3. Rekonstruksi persamaan linier byte-wise XOR ($F[i] = i \oplus \text{buf}_A[i] \oplus \text{buf}_B[i] \oplus 19$).
4. Eksekusi simbolik dan kalkulasi deterministik sesuai panduan standar **NIST SP 800-115 Section 4.2** (*Software Analysis and Reverse Engineering*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Teknik Obfuscation Stack Strings (CWE-653 / CWE-200):**
   - Penulis kode sering kali menghindari penyimpanan string sensitif (seperti kunci lisensi atau flag) pada segmen data statis (`.rodata` atau `.data`) agar tidak terdeteksi oleh utilitas inspeksi teks statis sederhana seperti `strings`.
   - Sebagai gantinya, string dibangun secara dinamis di atas tumpukan runtime dengan memecah rangkaian byte menjadi serangkaian integer 64-bit (*quadwords* / 8 byte per register):
     ```assembly
     movabs $0x2506e788e0db3e, %rax
     mov    %rax, -0x70(%rbp)
     movabs $0x1f2fffc6bfd92a4c, %rax
     mov    %rax, -0x68(%rbp)
     ...
     ```
2. **Keterbalikan Sempurna Operasi Aljabar XOR (Bitwise Invertibility):**
   - Algoritma transformasi biner tidak menggunakan kriptografi non-linier (seperti S-Box atau hashing satu arah), melainkan fungsi translasi berbasis bit:
     $$F[i] = i \oplus \text{buf}_A[i] \oplus \text{buf}_B[i] \oplus 19$$
   - Karena setiap komponen byte $\text{buf}_A[i]$ dan $\text{buf}_B[i]$ telah didefinisikan secara statis melalui nilai *quadword* di assembly, komputasi seluruh 48 byte flag dapat diselesaikan secara langsung tanpa kompilasi atau eksekusi interaktif biner.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Nilai Quadword Array A & B:**
   - Membaca konstanta numerik 64-bit dari `chall.S`:
     - Array A: `[166649011824203166, 2246226443284637900, 5443368435603081563, 6634115839532674854, -6741273775118318351 & 0xffffffffffffffff, 5353993955195766119]`
     - Array B: `[7871294989769368812, 6652410930181606323, 1224009049906308460, 2463296711132796444, -3950945058866805859 & 0xffffffffffffffff, 798037826989530220]`
2. **Serialisasi Little-Endian Byte Streams:**
   - Melakukan unpacking integer 64-bit ke dalam representasi byte little-endian (`struct.pack('<Q', val)`), membentuk dua buah buffer biner masing-masing berukuran 48 byte.
3. **Eksekusi Transformasi XOR:**
   - Melakukan loop iterasi $i = 0 \dots 47$:
     `flag[i] = chr(i ^ buf_a[i] ^ buf_b[i] ^ 19)`
4. **Hasil Rekonstruksi Flag:**
   - Nilai teks berhasil dipulihkan:
     `academy{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_0c8f18c}`
5. **Verifikasi Solver Mandiri:**
   - Menjalankan skrip `scripts/solve_102_lets_get_dynamic.py` yang memvalidasi integritas payload secara otomatis.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_0c8f18c}`
- **Komunitas Standar (CTF Format):** `CTF{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_0c8f18c}`
- **Native picoCTF Format:** `picoCTF{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_0c8f18c}`
- **Status Live Platform API:** Terverifikasi 100% valid (`HTTP 201 Created`, `"correct": true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Stack Strings pada Malware Analysis (LKS Incident Response & Forensik):**
   Pada modul LKS Cyber Security bidang Analisis Malware atau Reverse Engineering, analis sering menjumpai sampel malware yang mengaburkan nama domain C2 (*Command and Control*) atau string panggilan API menggunakan *stack strings*. Kemampuan membaca alur *immediate loading* pada assembler mempercepat identifikasi indikator kompromi (IoC).
2. **Mitigasi Rekayasa Perangkat Lunak Aman:**
   - Jangan mengandalkan obfuscation stack strings sebagai mekanisme perlindungan rahasia (*security through obscurity*).
   - Simpan kredensial atau rahasia otentikasi di luar biner menggunakan modul perangkat keras seperti TPM / HSM atau layanan manajemen rahasia terenkripsi.
3. **Penerapan Standar NIST SP 800-115:**
   Verifikasi ini mendemonstrasikan bahwa manipulasi aljabar linier dalam kode biner dapat direkayasa balik secara deterministik, menegaskan perlunya pengujian statis mendalam (*deep code inspection*) dalam pengujian penetrasi formal.
