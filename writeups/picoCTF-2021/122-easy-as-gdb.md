# Writeup: Easy as GDB (Challenge ID: 122)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Dynamic Binary Instrumentation & Reversible Permutation Analysis
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 300
- **Author:** Dylan McGuire
- **Flag:** `academy{I_5D3_A11DA7_f73c8ead}`

---

## Problem Statement & Scope
Tantangan `Easy as GDB` menyajikan berkas biner ELF 32-bit Linux (`brute`). Aplikasi meminta input flag dari pengguna, kemudian memproses string tersebut melalui fungsi permutasi transposisi berlapis dan masking XOR sebelum membandingkannya dengan array ciphertext byte terenkripsi yang tersimpan pada segmen data statis (`.rodata`).

Peserta diarahkan untuk memanfaatkan GDB Scripting / GDB Python API atau analisis matematika statis untuk mengekstrak string flag asli yang menghasilkan kecocokan ciphertext pada memori.

Ruang lingkup audit keamanan perangkat lunak dan analisis rekayasa balik ini meliputi:
1. Rekonstruksi graf kendali alur (*Control Flow Graph*) dan dekompilasi fungsi pengecekan pada ELF x86 32-bit.
2. Analisis matematis fungsi transposisi memori `permute()` dan pemetaan simetris pertukaran indeks (*pairwise buffer swapping*).
3. Pemulihan kunci XOR siklik 4-byte (`[0x5e, 0x07, 0x23, 0x07]`) dan ekstraksi ciphertext target (30 byte).
4. Penulisan skrip reproduksi pembalik permutasi mandiri sesuai panduan standar **NIST SP 800-115 Section 4.2** (*Software Analysis and Reverse Engineering*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Permutasi Deterministik Tanpa Entropi Kriptografis (CWE-653 / CWE-327):**
   - Fungsi `permute(buf, length, 1)` melakukan serangkaian pertukaran byte berulang dengan variabel langkah (*step*) mulai dari `1` hingga `length - 1` (`29`):
     ```c
     void swap_step(uint8_t *buf, int length, int step) {
         int i = 0;
         while (i < length - step + 1) {
             uint8_t tmp = buf[i];
             buf[i] = buf[i + step - 1];
             buf[i + step - 1] = tmp;
             i += step;
         }
     }
     ```
   - Operasi penukaran (*swap*) bersifat involutif (dapat dibalikkan dengan menukar kembali elemen yang sama). Oleh karena itu, inversi permutasi dapat dicapai secara eksak cukup dengan membalik urutan eksekusi langkah dari `length - 1` turun ke `1`.
2. **Kelemahan Masking XOR Siklik (Repeating Multi-Byte Key XOR):**
   - Setelah tahapan transposisi, program melakukan operasi XOR terhadap setiap byte ke-$i$ dengan konstanta berulang 4-byte:
     $$C[i] = P_{permuted}[i] \oplus K[i \pmod 4]$$
   - Karena operasi XOR adalah komutatif dan swa-invers ($A \oplus B = C \iff C \oplus B = A$), membalikkan enkripsi hanya membutuhkan un-XOR diikuti inversi langkah permutasi.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Ciphertext Target:**
   - Membaca 30 byte ciphertext dari memori `.rodata` biner `brute`:
     `7a 3f 64 63 3b 5a 16 7c 6d 43 6f 36 66 62 46 14 43 61 42 3f 58 01 58 34 62 3d 6a 30 3a 17`
2. **Inversi Permutasi Transposisi:**
   - Menjalankan algoritma pembalik langkah: untuk `step` mulai dari 29 turun ke 1, lakukan `swap(buf[i], buf[i + step - 1])` pada interval `step`.
3. **Dekripsi Masking XOR 4-Byte:**
   - Menerapkan kunci `[0x5e, 0x07, 0x23, 0x07]` pada setiap indeks $i \pmod 4$.
4. **Hasil Rekonstruksi Flag:**
   - Karakter terdekripsi menghasilkan string 30 karakter:
     `academy{I_5D3_A11DA7_f73c8ead}`
5. **Verifikasi Reproduksi Otomatis:**
   - Skrip `scripts/solve_122_easy_as_gdb.py` mengonfirmasi pemulihan flag secara instan tanpa memerlukan eksekusi dinamis GDB runtime yang lambat.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{I_5D3_A11DA7_f73c8ead}`
- **Komunitas Standar (CTF Format):** `CTF{I_5D3_A11DA7_f73c8ead}`
- **Native picoCTF Format:** `picoCTF{I_5D3_A11DA7_f73c8ead}`
- **Status Live Platform API:** Terverifikasi 100% valid (`HTTP 201 Created`, `"correct": true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Matematis vs Dynamic Scripting (LKS Reverse Engineering):**
   Peserta LKS Cyber Security kerap diarahkan menggunakan GDB scripting untuk menebak karakter per karakter melalui pencocokan instruksi. Namun, mengidentifikasi sifat matematis inversi permutasi memungkinkan pemecahan statis dalam hitungan milidetik dan bebas dari *noise* lingkungan OS.
2. **Hardening Algoritma Validasi Serial Kunci (Defensive Remediation):**
   - Hindari penggunaan skema transposisi deterministik statis tanpa fungsi derivasi kunci yang aman (seperti PBKDF2/Argon2).
   - Gunakan fungsi verifikasi berbasis *constant-time comparison* (`CRYPTO_memcmp`) dan HMAC-SHA256 untuk memvalidasi token tanpa membocorkan struktur internal byte ke memori biner.
3. **Kepatuhan NIST SP 800-115:**
   Dokumentasi audit ini membuktikan kepatuhan terhadap standar pengujian keamanan perangkat lunak terstruktur, mengisolasi titik kelemahan kriptografi kustom, dan menyediakan metode verifikasi reproduktif.
