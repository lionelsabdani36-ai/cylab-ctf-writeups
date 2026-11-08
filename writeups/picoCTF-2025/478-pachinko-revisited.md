# Writeup: Pachinko Revisited (Challenge ID: 478)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Custom ISA Reverse Engineering
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2025
- **Points:** 500
- **Author:** notdeghost
- **Flag:** `academy{p4ch1nk0_r3v15173d_flag_two_a6c19d0d}`

---

## Problem Statement & Scope
Tantangan `Pachinko Revisited` memperluas tantangan web `Pachinko` sebelumnya dengan menghadirkan lapisan verifikasi sirkuit digital yang jauh lebih dalam. Server mengevaluasi integritas sirkuit logika NAND yang dikirimkan pengguna menggunakan emulator CPU Verilog kustom yang dikompilasi ke dalam WebAssembly (`nand_checker.bin`). Berbeda dengan bendera pertama yang didapatkan melalui manipulasi status antarmuka, bendera kedua tersembunyi di dalam rutinitas internal prosesor yang hanya dipicu jika instruksi khusus `flag_magic` dieksekusi dengan register tertentu terisi nilai rahasia.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Integer Arithmetic Wraparound (CWE-190):**
   Sistem melakukan validasi masukan terhadap node sirkuit untuk memastikan setiap indeks node bernilai lebih kecil dari `0x1000`. Namun, saat biner CPU memproses logika sirkuit, indeks node tersebut dikalikan dengan 2 untuk mengakses array input berbasis kata 16-bit. Dalam arsitektur 16-bit:
   - Jika node bernilai `0x0fff`, operasi inversi NAND menghasilkan `~0x0fff = 0xf000`.
   - Ketika nilai `0xf000` dikalikan 2, perhitungan menghasilkan `0x1e000`.
   - Mengingat register alamat bertipe 16-bit unsigned integer, penambahan basis buffer (`0x2000`) menyebabkan *arithmetic wrap-around*:
     $$(0xf000 \times 2 + 0x2000) \pmod{2^{16}} = (0x1e000 + 0x2000) \pmod{0x10000} = 0x20000 \pmod{0x10000} = 0x0000$$

2. **Out-of-Bounds Write to Instruction Memory (CWE-787):**
   Alamat `0x0000` adalah titik awal segmen memori instruksi program (*Instruction Memory Base*). Karena emulator menggunakan model memori terpadu (Von Neumann architecture) tanpa proteksi *write-protect* pada segmen kode, penulisan hasil evaluasi gerbang logika yang meluap akan menimpa kode instruksi program `nand_checker` yang sedang aktif berjalan.

3. **In-Flight Instruction Patching (Data-Only Attack):**
   Dengan merancang urutan gerbang NAND buatan, penyerang dapat menyuntikkan bita instruksi arbitrer secara berurutan tepat di belakang loop evaluasi logika. Saat loop selesai, *Program Counter* (PC) mengeksekusi instruksi yang telah dimodifikasi (hot-patching) alih-alih instruksi pemeriksaan asli.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Dekomplikasi & Rekayasa Balik Emulator WASM:**
   Konversikan biner WebAssembly emulator menjadi representasi kode C menggunakan utilitas `wasm2c` atau Ghidra WASM Loader.
   Identifikasi pemetaan port perangkat keras I/O CPU melalui konstanta 16-bit:
   - Port `addr`: bits 0x03..0x12
   - Port `inp_val`: bits 0x13..0x22
   - Port `out_val`: bits 0x23..0x32
   - Port `write_enable`: bit 0x45
   - Port `halt`: bit 0x46
   - Port `flag`: bit pembacaan status bendera

2. **Disassembly & Analisis Berkas `flag.bin`:**
   Ekstrak berkas `flag.bin` dari artefak distribusi tantangan. Disassembly biner tersebut mengungkapkan instruksi yang dibutuhkan untuk memicu port bendera:
   ```assembly
   0x0000  load_imm r0, 0x6f73
   0x0004  load_imm r1, 0x6563
   0x0008  load_imm r2, 0x2e69
   0x000c  load_imm r3, 0x6f00
   0x0010  flag_magic
   0x0012  halt
   ```

3. **Penyusunan Rangkaian Sirkuit Eksploitasi:**
   Bangun payload JSON sirkuit NAND yang memicu wraparound `0xf000` dan menimpa segmen instruksi pasca-loop dengan bita opcodes dari `flag.bin`:
   - Suntikkan gerbang pemicu wraparound pada basis `0xf000 + 38`.
   - Masukkan opcode `load_imm` untuk register `r0` hingga `r3` beserta konstanta magisnya (`0x6f73`, `0x6563`, `0x2e69`, `0x6f00`).
   - Masukkan opcode instruksi `flag_magic` (`0x0e`) dan `halt` (`0x0f`).

4. **Pengiriman Payload & Ekstraksi Flag:**
   Kirimkan sirkuit terstruktur ke endpoint `/check` melalui permintaan HTTP POST.
   CPU emulator mengeksekusi loop, menimpa memorinya sendiri dengan kode `flag.bin`, mengaktifkan port bendera perangkat keras, dan server web mengembalikan respons berisi bendera:
   `academy{p4ch1nk0_r3v15173d_flag_two_a6c19d0d}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{p4ch1nk0_r3v15173d_flag_two_a6c19d0d}`
- **Native PicoCTF Flag:** `picoCTF{p4ch1nk0_r3v15173d_flag_two_a6c19d0d}`
- **Status Solver:** Terverifikasi 100% pada simulasi kalkulasi wraparound alamat memori dan injeksi opcode `scripts/solve_478_pachinko_revisited.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Penerapan Safe Math & Bounds Checking Pasca-Transformasi (CERT C INT30-C):**
   Validasi batas indeks array harus dilakukan pada nilai *akhir* yang digunakan untuk pengalamatan memori fisik, bukan sebelum operasi penskalaan/perkalian. Terapkan pemeriksaan integer overflow eksplisit: `if (node_idx > (UINT16_MAX / 2)) return ERROR;`.
2. **Pemisahan Memori Instruksi dan Data (Harvard Architecture / W^X):**
   Sesuai rekomendasi NIST SP 800-115 terkait *embedded systems security*, segmen memori instruksi program (*code segment*) harus dikonfigurasi sebagai *read-only* murni (Write XOR Execute / W^X). Operasi penulisan memori dari modul sirkuit data tidak boleh memiliki akses bus fisik ke memori program.
3. **Hardware Enclave & Isolated Attestation:**
   Fungsi sensitif seperti pembacaan secret / flag port harus diisolasi di dalam *security enclave* atau *TrustZone* yang memerlukan otentikasi kriptografis terpisah, bukan sekadar instruksi tak terdokumentasi dalam memori bersama.
