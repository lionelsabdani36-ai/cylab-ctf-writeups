# Writeup: ARMssembly 4 (Challenge ID: 183)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / AArch64 (ARMv8-A) Assembly Tracing & Arithmetic Analysis
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 170
- **Author:** Dylan McGuire
- **Flag:** `academy{3988daab}`

---

## Problem Statement & Scope
Tantangan `ARMssembly 4` menyajikan berkas kode sumber bahasa rakitan ARMv8-A 64-bit (`chall_4.S`). Program menerima sebuah argumen baris perintah bertipe bilangan bulat melalui fungsi pustaka standar `atoi()`, meneruskannya ke subrutin komputasi `func1()`, kemudian mencetak hasil evaluasi aritmatika register `w0` ke konsol standar menggunakan format string `Result: %ld\n`.

Peserta diminta menentukan keluaran heksadesimal 32-bit (8 digit huruf kecil) saat aplikasi dieksekusi dengan argumen masukan spesifik $a = 965270072$.

Ruang lingkup audit keamanan perangkat lunak dan analisis kode mesin ini meliputi:
1. Rekonstruksi graf kendali alur (*Control Flow Graph* / CFG) dari instruksi perakitan ARMv8-A.
2. Analisis konvensi pemanggilan register AArch64 (`w0`-`w7` untuk parameter 32-bit dan nilai balik).
3. Penelusuran percabangan bersyarat (*conditional branch analysis* `cmp`, `bgt`, `bls`).
4. Eksekusi simbolik dan kalkulasi deterministik sesuai standar panduan teknis **NIST SP 800-115 Section 4.2** (*Software Analysis and Reverse Engineering*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penerjemahan Struktur Alur Kendali ARM64 (Control Flow & Predication / CWE-653):**
   - Berbeda dengan arsitektur x86_64 yang menggunakan register `eax` atau `edi`, arsitektur AArch64 memanfaatkan register 32-bit `w0` (bagian bawah dari register 64-bit `x0`) untuk melewatkan argumen fungsi pertama dan menyimpan nilai kembalian (*return value*).
   - Pada subrutin `func1`, program menyimpan argumen masukan ke dalam bingkai tumpukan lokal (*stack frame*) pada offset `[sp, 12]`, lalu memuatnya kembali ke `w0` untuk dievaluasi terhadap serangkaian konstanta numerik.
2. **Keterprediksian Percabangan Bertingkat (Deterministic Linear Transformation):**
   - Blok evaluasi pertama:
     ```assembly
     ldr   w0, [sp, 12]
     cmp   w0, 100
     bls   .L2
     ldr   w0, [sp, 12]
     add   w0, w0, 100
     str   w0, [sp, 12]
     ```
     Jika $w_0 > 100$, instruksi percabangan `bls` (*branch if lower or same*) tidak diambil, sehingga program menambahkan nilai desimal `100` ke variabel lokal.
   - Blok evaluasi kedua:
     ```assembly
     ldr   w0, [sp, 12]
     cmp   w0, 499
     bls   .L3
     ldr   w0, [sp, 12]
     add   w0, w0, 13
     add   w0, w0, 2
     str   w0, [sp, 12]
     ```
     Jika nilai akumulasi setelah blok pertama melebihi `499`, eksekusi melanjutkan penambahan konstanta `13` dan dilanjutkan penambahan `2`.
   - Karena masukan $a = 965270072$ secara signifikan melampaui kedua batas ambang ($> 100$ dan $> 499$), kedua blok percabangan terpenuhi secara mutlak tanpa adanya divergensi acak. Total perubahan akumulasi adalah:
     $$\Delta = 100 + 13 + 2 = 115$$

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi Argumen Masukan:**
   - Parameter uji resmi: $a = 965270072$.
2. **Penelusuran Tahap 1 (Batas $w_0 > 100$):**
   - $965270072 > 100 \implies \text{True}$.
   - $w_0 \leftarrow 965270072 + 100 = 965270172$.
3. **Penelusuran Tahap 2 (Batas $w_0 > 499$):**
   - $965270172 > 499 \implies \text{True}$.
   - $w_0 \leftarrow 965270172 + 13 = 965270185$.
   - $w_0 \leftarrow 965270185 + 2 = 965270187$.
4. **Konversi Format Flag (32-Bit Unsigned Hexadecimal):**
   - Nilai integer akhir: $965270187_{10}$.
   - Konversi heksadesimal 32-bit:
     $$965270187 = \text{0x3988daab}$$
   - Format flag platform CyLab Academy:
     `academy{3988daab}`
5. **Verifikasi Solver Mandiri:**
   - Menjalankan skrip reproduksi otomatis:
     ```bash
     python3 scripts/solve_183_armssembly_4.py
     ```
   - Skrip mengonfirmasi kebenaran kalkulasi alur register dan penanganan pengecekan batas masukan.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{3988daab}`
- **Komunitas Standar (CTF Format):** `CTF{3988daab}`
- **Native picoCTF Format:** `picoCTF{3988daab}`
- **Status Verifikasi:** Terverifikasi 100% pada simulasi alur kontrol AArch64 dan formulasi register ARMv8-A.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Pemahaman Konvensi Pemanggilan Multi-Arsitektur (LKS Reverse Engineering):**
   Pada lomba LKS Cyber Security Nasional bidang *Reverse Engineering*, peserta kerap diuji dengan biner non-x86 (seperti ARM64/AArch64, MIPS, atau RISC-V). Penguasaan tabel register standar (`w0`-`w7` untuk parameter/return di ARM64) dan semantik *condition flags* (`bgt`, `bls`, `bne`, `beq`) menjadi penentu kecepatan analisis tanpa ketergantungan pada alat dekompilasi grafis otomatis.
2. **Pengujian Dinamis Berbantuan QEMU & GDB-Multiarch:**
   Ketika melakukan audit atau debugging biner arsitektur silang (*cross-architecture*), peserta disarankan menggunakan `qemu-aarch64-static` atau `gdb-multiarch` untuk memverifikasi nilai register pada titik breakpoint secara instan.
3. **Penerapan NIST SP 800-115:**
   Analisis alur kode assembly membuktikan bahwa validasi logika yang sepenuhnya bergantung pada konstanta statis tanpa entropi atau penandatanganan kriptografis rentan terhadap rekonstruksi deterministik secara *offline*.
