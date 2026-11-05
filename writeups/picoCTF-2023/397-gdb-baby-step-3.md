# Writeup: GDB baby step 3 (Challenge ID: 397)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / x86_64 Little-Endian Memory Layout & GDB Inspection
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{0x6bc96222}`

---

## Problem Statement & Scope

Diberikan sebuah berkas executable Linux ELF 64-bit bernama `debugger0_c`. Konstanta numerik heksadesimal `0x2262c96b` dimuat ke dalam memori pada fungsi `main`. Peserta diminta menganalisis representasi byte fisik memori pada alamat tersebut menggunakan GNU Debugger (`gdb`) atau disassembler dengan perintah `x/4xb addr`, lalu menyusun keempat byte tersebut ke dalam format flag `academy{0x...}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Prinsip Endianness & Little-Endian pada Arsitektur x86_64 (NIST SP 800-115 Memory Inspection):**
   - Arsitektur prosesor x86 dan x86_64 mengimplementasikan konvensi penyimpanan memori berorientasi *Little-Endian*.
   - Dalam sistem Little-Endian, ketika sebuah nilai skalar multi-byte (seperti tipe data `int` atau `uint32_t` 4-byte) disimpan ke memori, byte paling tidak signifikan (*Least Significant Byte / LSB*) disimpan pada alamat memori paling rendah (posisi fisik pertama), sedangkan byte paling signifikan (*Most Significant Byte / MSB*) disimpan pada alamat tertinggi.
2. **Dekomposisi Instruksi Disassembly Fungsi `main`:**
   ```asm
   0000000000401106 <main>:
     401106: endbr64 
     40110a: push   rbp
     40110b: mov    rbp,rsp
     40110e: mov    DWORD PTR [rbp-0x14],edi
     401111: mov    QWORD PTR [rbp-0x20],rsi
     401115: mov    DWORD PTR [rbp-0x4],0x2262c96b   ; memuat dword konstan ke stack
     40111c: mov    eax,DWORD PTR [rbp-0x4]
     40111f: pop    rbp
     401120: ret
   ```
   - Baris `401115: c7 45 fc 6b c9 62 22`: Instruksi `mov DWORD PTR [rbp-0x4], 0x2262c96b` mengalokasikan ruang 4-byte pada frame stack lokal.
   - Konstanta 32-bit `0x2262c96b` terbagi menjadi 4 byte:
     - Byte 0 (LSB): `0x6b`
     - Byte 1: `0xc9`
     - Byte 2: `0x62`
     - Byte 3 (MSB): `0x22`
3. **Pemetaan Alamat Memori Fisik:**
   - Alamat `[rbp-0x4]` $\rightarrow$ `0x6b`
   - Alamat `[rbp-0x3]` $\rightarrow$ `0xc9`
   - Alamat `[rbp-0x2]` $\rightarrow$ `0x62`
   - Alamat `[rbp-0x1]` $\rightarrow$ `0x22`
   - Perintah pemeriksaan GDB `x/4xb $rbp-0x4` membaca 4 byte sekuensial mulai dari alamat terendah, menghasilkan output terurut: `0x6b  0xc9  0x62  0x22`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh biner `debugger0_c` dari CDN resmi CyLab:
   ```bash
   curl -sL https://challenge-files.cylabacademy.net/library/5eb60afe8ad6df789decfd9d5af027dc8184bfbc20e953f76ed38bd9ce3d9582/debugger0_c -o debugger0_c
   chmod +x debugger0_c
   ```
2. Analisis menggunakan GDB dengan menempatkan breakpoint tepat setelah pemuatan memori (`*0x40111c`):
   ```bash
   gdb -batch -ex "break *0x40111c" -ex "run" -ex "x/4xb \$rbp-0x4" debugger0_c
   ```
   Output eksekusi runtime:
   ```text
   Breakpoint 1, 0x000000000040111c in main ()
   0x7fffffffdb2c:	0x6b	0xc9	0x62	0x22
   ```
3. Alternatif verifikasi statis melalui opcode mesin `objdump`:
   ```bash
   objdump -d -M intel debugger0_c | grep "mov.*DWORD PTR \[rbp-0x4\]"
   ```
   Opcode: `c7 45 fc 6b c9 62 22`. Empat byte terakhir secara gamblang memperlihatkan urutan byte Little-Endian: `6b c9 62 22`.
4. Rangkai keempat byte heksadesimal ke dalam format flag yang ditentukan:
   `0x6b` + `0xc9` + `0x62` + `0x22` $\rightarrow$ `academy{0x6bc96222}`.
5. Jalankan script solver otomatis `scripts/solve_397_gdb_baby_step_3.py`.
6. Kirim submisi flag ke endpoint REST API: `POST /api/submissions/` dengan payload `{"challenge": 397, "flag": "academy{0x6bc96222}"}`.

---

## Flag & Verifikasi

- **Flag:** `academy{0x6bc96222}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan HTTP Status `201 Created`:
  ```json
  {"user": 1072359, "challenge": 397, "flag": "academy{0x6bc96222}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Pemahaman mendalam mengenai arsitektur mesin register dan hierarki memori Little-Endian vs Big-Endian pada platform Linux x86/x64.
  - Penguasaan syntax format pemeriksaan memori GDB (`x/nfu addr`: *number*, *format*, *unit size*) yang esensial dalam debugging eksploitasi buffer overflow dan analisis heap.
- **Mitigasi Defensif:**
  - Pada transmisi data jaringan (network protocols) dan pertukaran berkas portabel lintas platform, konversi selalu data lokal Little-Endian ke format *Network Byte Order* (Big-Endian) menggunakan fungsi standar POSIX `htonl()` / `htons()` guna mencegah kesalahan interpretasi nilai integer (*endianness misalignment*).
