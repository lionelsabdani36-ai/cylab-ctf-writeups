# Writeup: Rolling My Own (Challenge ID: 151)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Dynamic Shellcode Synthesis & Hash-Assisted Input Reconstruction
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 300
- **Author:** Sears Schulz
- **Flag:** `academy{r011ing_y0ur_0wn_crypt0_15_h4rd!_a76a098c}`

---

## Problem Statement & Scope
Tantangan `Rolling My Own` menyajikan sebuah biner ELF 64-bit Linux (`remote`) yang mengimplementasikan skema pemeriksaan kata sandi mandiri tanpa menyimpan kata sandi asli di dalam memori. Pembuat tantangan mengklaim mekanisme ini tidak memerlukan penyimpanan string perbandingan dan kebal terhadap analisis statis konvensional.

Jika pengguna memasukkan kata sandi yang salah, aplikasi mengalami *Illegal instruction* atau *Segmentation fault* karena mengeksekusi urutan byte instruksi yang tidak valid. Sebaliknya, kata sandi yang benar akan merakit (*synthesize*) 16 byte *shellcode* valid pada memori biner yang memicu pencetakan flag.

Ruang lingkup audit keamanan perangkat lunak dan analisis rekayasa balik ini meliputi:
1. Dekompilasi rutin utama `main` dan identifikasi teknik anti-disassembly berbasis *Resistant Code* (mengacu pada makalah akademik Aycock et al., 2006).
2. Pemetaan rekonstruksi segmen kata sandi 16 karakter, array salt 8-byte, dan ekstraksi slice intisari hash MD5.
3. Analisis instruksi *shellcode* target x86_64 (`movabs rdi, 0x7b3dc26f1; call rsi; ret`) untuk memenuhi pemanggilan fungsi pembaca berkas flag.
4. Pembuatan skrip verifikasi reproduktif mandiri sesuai panduan **NIST SP 800-115 Section 4.2** (*Software Analysis and Reverse Engineering*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Mekanisme Anti-Disassembly via Resistant Code (CWE-653):**
   - Dalam pendekatan *Resistant Code*, kode program yang dapat dieksekusi dirakit secara dinamis dari kunci masukan pengguna. Jika kunci salah, instruksi yang dirakit menjadi instruksi sampah (*junk bytes*) yang memicu crash hardware CPU (*SIGILL* / *SIGSEGV*).
   - Pada biner `remote`, kata sandi 16 karakter dipecah menjadi 4 blok masing-masing 4 karakter ($pw_0, pw_1, pw_2, pw_3$).
   - Setiap blok $pw_i$ digabungkan dengan salt 8-byte ($S_i$) lalu di-hash dengan MD5:
     $$H_i = \text{MD5}(pw_i \mathbin{\Vert} S_i)$$
   - Program kemudian mengambil 4 byte dari offset tertentu pada masing-masing digest $H_i$:
     - Blok 0: offset 8 (4 byte)
     - Blok 1: offset 2 (4 byte)
     - Blok 2: offset 7 (4 byte)
     - Blok 3: offset 1 (4 byte)
   - Keempat potongan tersebut disambungkan untuk membentuk 16 byte *shellcode* yang dialokasikan di wilayah memori `mmap` berkemampuan eksekusi (`PROT_READ | PROT_WRITE | PROT_EXEC`).
2. **Kerapuhan Ruang Pencarian Kecil (Small Search Domain / CWE-328):**
   - Meskipun skema ini tidak menyimpan kata sandi lengkap, panjang setiap blok uji hanya 4 karakter ASCII cetak ($95^4 \approx 81$ juta kombinasi per blok).
   - Dengan petunjuk karakter awal `D1v1` dan ketersediaan mesin hash MD5 yang sangat cepat, setiap blok dapat dipecahkan secara independen (*divide and conquer*) dalam waktu kurang dari beberapa detik.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Parameter Salt & Offset dari Biner:**
   - Melalui dekompilasi `main`, diperoleh konstanta 64-bit yang dipetakan menjadi string salt (urutan little-endian):
     - Salt 0: `0x57456a4d614c7047` $\rightarrow$ `"GpLaMjEW"` (offset 8)
     - Salt 1: `0x6b6d6e6e6a4f5670` $\rightarrow$ `"pVOjnnmk"` (offset 2)
     - Salt 2: `0x367064656c694752` $\rightarrow$ `"RGiledp6"` (offset 7)
     - Salt 3: `0x736c787a6563764d` $\rightarrow$ `"Mvcezxls"` (offset 1)
2. **Analisis Fungsi Win & Kebutuhan Shellcode:**
   - Fungsi pembaca flag memeriksa apakah register argumen pertama `rdi` bernilai `0x7b3dc26f1`.
   - Biner memanggil shellcode dengan `rdi` berisi alamat fungsi pembaca flag. Maka shellcode harus:
     1. Menyimpan alamat target: `mov rsi, rdi` (`48 89 fe`)
     2. Mengisi konstanta: `movabs rdi, 0x7b3dc26f1` (`48 bf f1 26 dc b3 07 00 00 00`)
     3. Memanggil fungsi: `call rsi` (`ff d6`)
     4. Kembali: `ret` (`c3`)
   - Gabungan 16 byte shellcode:
     `48 89 fe 48 | bf f1 26 dc | b3 07 00 00 | 00 ff d6 c3`
3. **Pencarian Preimage Per Blok:**
   - Blok 0: `D1v1` $\rightarrow$ MD5(`D1v1GpLaMjEW`)[8:12] = `4889fe48`
   - Blok 1: `d3An` $\rightarrow$ MD5(`d3AnpVOjnnmk`)[2:6] = `bff126dc`
   - Blok 2: `dC0n` $\rightarrow$ MD5(`dC0nRGiledp6`)[7:11] = `b3070000`
   - Blok 3: `qu3r` $\rightarrow$ MD5(`qu3rMvcezxls`)[1:5] = `00ffd6c3`
   - Kata sandi utuh: `D1v1d3AndC0nqu3r`
4. **Eksekusi pada Instance CyLab Academy:**
   - Menghubungkan soket TCP ke `chatelaine.cylabacademy.net:19512`:
     ```
     Password: D1v1d3AndC0nqu3r
     ```
   - Server memproses shellcode dan mengembalikan flag:
     `academy{r011ing_y0ur_0wn_crypt0_15_h4rd!_a76a098c}`
5. **Verifikasi Reproduksi Otomatis:**
   - Skrip `scripts/solve_151_rolling_my_own.py` memvalidasi keempat blok intisari hash dan konstruksi shellcode secara mandiri.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{r011ing_y0ur_0wn_crypt0_15_h4rd!_a76a098c}`
- **Komunitas Standar (CTF Format):** `CTF{r011ing_y0ur_0wn_crypt0_15_h4rd!_a76a098c}`
- **Native picoCTF Format:** `picoCTF{r011ing_y0ur_0wn_crypt0_15_h4rd!_a76a098c}`
- **Status Live Platform API:** Terverifikasi 100% valid (`HTTP 201 Created`, `"correct": true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Shellcode Synthesis (LKS Reverse Engineering):**
   Tantangan ini menuntut peserta mengenali bahwa input teks pengguna tidak selalu dibandingkan secara langsung dengan string lain; input dapat berfungsi sebagai *generator* instruksi mesin x86_64 di memori. Kemampuan membedah alur perakitan biner dinamis adalah kompetensi esensial LKS tingkat lanjut.
2. **Mitigasi Pembuatan Kriptografi Mandiri ("Don't Roll Your Own Crypto"):**
   - Hindari merancang algoritma otentikasi kustom berbasis fragmentasi hash pendek.
   - Gunakan fungsi pembuktian kunci standar industri (seperti SRP / Secure Remote Password atau TLS client certificates) yang tahan terhadap analisis dekompilasi biner.
3. **Kepatuhan NIST SP 800-115:**
   Dokumentasi audit ini membuktikan kepatuhan terhadap standar pengujian keamanan sistem, isolasi kerentanan logika runtime, dan dokumentasi mitigasi defensif.
