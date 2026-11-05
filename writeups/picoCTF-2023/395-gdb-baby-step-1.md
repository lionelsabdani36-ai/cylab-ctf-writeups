# Writeup: GDB baby step 1 (Challenge ID: 395)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / x86_64 ELF Binary Disassembly & GDB Analysis
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{549698}`

---

## Problem Statement & Scope

Diberikan sebuah berkas executable Linux ELF 64-bit bernama `debugger0_a`. Peserta diminta menganalisis fungsi utama `main` menggunakan debugger (GDB) atau disassembler untuk menentukan nilai akhir yang tersimpan dalam register akumulator `eax` sebelum fungsi melakukan *return*, lalu mengonversinya ke format desimal.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Biner ELF x86_64 & Resolusi Simbol (NIST SP 800-115 Static Analysis):**
   - Berkas biner `debugger0_a` merupakan file biner standar Linux bertipe `ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, not stripped`.
   - Karena biner tidak mengalami proses *stripping* tabel simbol (`not stripped`), seluruh nama fungsi (termasuk fungsi `main`) tetap tercatat di dalam seksi `.symtab` dan `.strtab`, memudahkan alat disassembler dan debugger untuk mengisolasi titik masuk eksekusi fungsi.
2. **System V AMD64 ABI & Akumulator Nilai Balik:**
   - Standar ABI pada sistem operasi turunan Unix (Linux) menetapkan register `rax` (dan bagian 32-bit terbawahnya `eax`) sebagai penyimpan nilai pengembalian (*return value*) dari fungsi bernilai integer (misalnya `int main(int argc, char **argv)`).
3. **Analisis Instruksi Perakitan Fungsi `main`:**
   ```asm
   0000000000001129 <main>:
       1129: f3 0f 1e fa    endbr64 
       112d: 55             push   rbp
       112e: 48 89 e5       mov    rbp,rsp
       1131: 89 7d fc       mov    DWORD PTR [rbp-0x4],edi
       1134: 48 89 75 f0    mov    QWORD PTR [rbp-0x10],rsi
       1138: b8 42 63 08 00 mov    eax,0x86342
       113d: 5d             pop    rbp
       113e: c3             ret
   ```
   - Baris `1138: mov eax, 0x86342`: Instruksi ini memindahkan nilai konstan langsung heksadesimal `0x86342` ke dalam register `eax`.
   - Tidak ada instruksi lain yang memodifikasi `eax` sebelum instruksi `ret` dieksekusi.
4. **Konversi Bilangan Heksadesimal ke Desimal:**
   - $0x86342_{16} = (8 \times 16^4) + (6 \times 16^3) + (3 \times 16^2) + (4 \times 16^1) + (2 \times 16^0)$
   - $= 524288 + 24576 + 768 + 64 + 2 = 549698_{10}$.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh berkas biner `debugger0_a` dari repository/CDN CyLab:
   ```bash
   curl -sL https://challenge-files.cylabacademy.net/library/03b038548e2a34973bde05a78fadc1f09467a1d03ffbfb9e4b48bd44e87c0e70/debugger0_a -o debugger0_a
   chmod +x debugger0_a
   ```
2. Analisis disassembled code menggunakan `objdump`:
   ```bash
   objdump -d -M intel debugger0_a | grep -A 10 "<main>:"
   ```
   Atau gunakan GDB secara interaktif:
   ```bash
   gdb -batch -ex "file debugger0_a" -ex "disassemble main"
   ```
   Output:
   ```text
   Dump of assembler code for function main:
      0x0000000000001129 <+0>:     endbr64 
      0x000000000000112d <+4>:     push   rbp
      0x000000000000112e <+5>:     mov    rbp,rsp
      0x0000000000001131 <+8>:     mov    DWORD PTR [rbp-0x4],edi
      0x0000000000001134 <+11>:    mov    QWORD PTR [rbp-0x10],rsi
      0x0000000000001138 <+15>:    mov    eax,0x86342
      0x000000000000113d <+20>:    pop    rbp
      0x000000000000113e <+21>:    ret
   ```
3. Ekstraksi konstanta `0x86342` dan hitung nilai desimalnya dalam Python:
   ```python
   int("0x86342", 16) # Output: 549698
   ```
4. Verifikasi kebenaran solusi melalui skrip otomatis `scripts/solve_395_gdb_baby_step_1.py`.
5. Kirim submisi token flag ke endpoint REST API: `POST /api/submissions/` dengan payload `{"challenge": 395, "flag": "academy{549698}"}`.

---

## Flag & Verifikasi

- **Flag:** `academy{549698}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan HTTP Status `201 Created`:
  ```json
  {"user": 1072359, "challenge": 395, "flag": "academy{549698}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Penguasaan dasar penggunaan alat analisis dinamis dan statis GNU Debugger (`gdb`) dan `objdump` pada platform Linux.
  - Memahami struktur fungsi dasar bahasa C terkompilasi (function prologue, body, dan epilogue) dan peran register nilai kembalian.
- **Mitigasi Defensif:**
  - Pada rilis perangkat lunak komersial/produksi, lakukan stripping simbol biner (`strip -s`) serta kompilasi dengan optimasi `LTO` (*Link Time Optimization*) guna menghapus metadata simbolis yang memudahkan reverse engineering oleh penyerang.
