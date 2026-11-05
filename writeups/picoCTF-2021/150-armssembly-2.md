# Writeup: ARMssembly 2 (Challenge ID: 150)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / ARMv8-A Assembly Tracing
- **Difficulty:** Hard
- **Author:** Dylan McGuire
- **Event:** picoCTF 2021
- **Points:** 90
- **Flag:** `academy{e815ef32}`

---

## Problem Statement & Scope
Diberikan berkas assembly arsitektur ARM 64-bit (AArch64 / ARMv8-A) bernama `chall_2.S`. Program menerima argumen baris perintah string angka yang dikonversi menggunakan `atoi()`, diproses oleh fungsi `func1()`, dan dicetak ke layar. Analis diminta menentukan nilai kembalian fungsi saat dipanggil dengan parameter integer $a = 2729572966$. Format flag diserahkan dalam representasi heksadesimal 32-bit huruf kecil tanpa prefix `0x` dibungkus format `academy{XXXXXXXX}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Konvensi Register ARMv8-A (AArch64 Procedure Call Standard / AAPCS64):**
   - Register `x0` - `x7` bertindak sebagai register parameter dan nilai kembalian. Register dengan prefiks `w` merepresentasikan separuh bawah 32-bit dari register 64-bit terkait (`w0` adalah 32-bit terbawah dari `x0`).
   - Register `wzr` merepresentasikan register nol 32-bit (Zero Register), yang selalu bernilai `0`.

2. **Semantik Flag Status dan Percabangan Bersyarat `bcc` pada ARM:**
   - Instruksi `cmp w1, w0` melakukan pengurangan biner $w1 - w0$ dan memperbarui flag prosesor (NZCV).
   - Pada arsitektur ARM, flag Carry ($C$) bekerja dengan konvensi "No Borrow":
     - Jika $w1 \ge w0$ (tanpa peminjaman), flag $C = 1$.
     - Jika $w1 < w0$ (terjadi peminjaman / borrow), flag $C = 0$.
   - Instruksi `bcc` (Branch if Carry Clear, sinonim dengan `blo` / Branch if Lower) melompat jika $C == 0$. Ini mengimplementasikan evaluasi perbandingan bilangan bulat tak bertanda (unsigned integer comparison):
     $$\text{Lompat ke } .L3 \iff w1 < w0 \quad (\text{unsigned})$$

3. **Struktur Loop Akumulasi Linear:**
   - Variabel pencacah iterasi $i$ diinisialisasi dari `0` dan bertambah `1` setiap iterasi hingga mencapai nilai batas $w0$.
   - Variabel akumulator diinisialisasi dari `0` dan bertambah `3` pada setiap putaran loop:
     $$\text{accumulator} = (w0 \times 3) \pmod{2^{32}}$$

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pemetaan Stack Frame `func1`:**
   - Prolog: `sub sp, sp, #32`
   - Penyimpanan parameter input: `str w0, [sp, 12]`
   - Inisialisasi akumulator: `str wzr, [sp, 24]` ($\text{acc} = 0$)
   - Inisialisasi indeks counter: `str wzr, [sp, 28]` ($i = 0$)
   - Lompatan awal: `b .L2`

2. **Analisis Tubuh Perulangan (`.L3` dan `.L2`):**
   - Pada `.L2`:
     - Muat $i$: `ldr w1, [sp, 28]`
     - Muat target batas: `ldr w0, [sp, 12]`
     - Bandingkan: `cmp w1, w0`
     - Evaluasi: `bcc .L3` (loop berulang selama $i < w0$)
   - Pada `.L3`:
     - Tambahkan akumulator: `acc = acc + 3`
     - Tambahkan indeks: $i = i + 1$
   - Pada saat terminasi ($i == w0$):
     - Muat hasil: `ldr w0, [sp, 24]`
     - Kembalikan ke pemanggil via register `w0`.

3. **Perhitungan Aritmetika Modulo 32-bit:**
   - Input argumen $a = 2729572966$ (`0xa2b1fa66` dalam heksadesimal).
   - Perkalian langsung:
     $$2729572966 \times 3 = 8188718898$$
   - Reduksi terhadap batas register 32-bit ($2^{32} = 4294967296$):
     $$8188718898 \pmod{4294967296} = 3893751602$$
   - Konversi ke format heksadesimal 32-bit lower-case:
     $$3893751602 = \text{0xe815ef32} \implies \text{e815ef32}$$

4. **Validasi Solver Reproduktif:**
   ```bash
   python3 scripts/solve_150_armssembly_2.py
   ```
   Output: `Flag: academy{e815ef32}`

---

## Flag & Verifikasi
- **Flag:** `academy{e815ef32}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons status HTTP 201 Created dengan hasil validasi `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Takeaway LKS:** Penguasaan arsitektur non-x86 (khususnya ARM AArch64) menjadi standar penting dalam kompetisi LKS Cyber Security modern seiring meluasnya adopsi perangkat IoT, mobile, dan server cloud berbasis ARM. Pemahaman spesifik tentang flag Carry pada arsitektur ARM (konvensi inverted borrow dibanding x86) sangat krusial agar tidak salah menentukan arah lompatan bersyarat (`bcc` vs `jnc`).
- **Mitigasi Defensif:** Penulisan perulangan akumulatif dalam kode sumber C/C++ yang dapat memproses input pengguna hingga skala $2^{31}$ berisiko menyebabkan loop denial of service (CPU starvation) jika waktu eksekusi sebanding dengan nilai input ($O(N)$). Operasi harus disederhanakan secara aljabar menjadi perkalian langsung ($O(1)$) dengan validasi batas input (`input <= MAX_ALLOWED`).
