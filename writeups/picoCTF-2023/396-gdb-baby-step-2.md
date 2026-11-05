# Writeup: GDB baby step 2 (Challenge ID: 396)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / x86_64 Dynamic Analysis & Loop Tracing
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{307019}`

---

## Problem Statement & Scope

Diberikan sebuah berkas biner Linux ELF 64-bit bernama `debugger0_b`. Peserta diminta mengevaluasi eksekusi alur kontrol loop akumulasi di dalam fungsi `main` menggunakan analisis dinamis (GDB) atau pemodelan matematis statis guna menentukan nilai akhir register akumulator `eax` tepat sebelum fungsi berakhir.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Pola Perulangan Perakitan x86_64 (NIST SP 800-115 Dynamic/Static Analysis):**
   - Pola perulangan `for (i = 0; i < limit; i++)` dikompilasi ke dalam pola percabangan bersyarat dengan struktur:
     - Inisialisasi variabel loop (`i = 0`).
     - Lompatan awal ke titik komparasi (`jmp <eval>`).
     - Badan perulangan (*loop body*) yang memodifikasi akumulator dan menambahkan variabel counter (`i++`).
     - Titik komparasi dan percabangan kembali (`cmp i, limit` diikuti `jl <loop_body>`).
2. **Dekomposisi Instruksi Disassembly Fungsi `main`:**
   ```asm
   0000000000401106 <main>:
     401106: endbr64 
     40110a: push   rbp
     40110b: mov    rbp,rsp
     40110e: mov    DWORD PTR [rbp-0x14],edi
     401111: mov    QWORD PTR [rbp-0x20],rsi
     401115: mov    DWORD PTR [rbp-0x4],0x1e0da   ; acc = 0x1e0da
     40111c: mov    DWORD PTR [rbp-0xc],0x25f     ; limit = 0x25f
     401123: mov    DWORD PTR [rbp-0x8],0x0       ; i = 0
     40112a: jmp    401136 <main+0x30>            ; lompat ke evaluasi kondisi
     40112c: mov    eax,DWORD PTR [rbp-0x8]       ; loop body: eax = i
     40112f: add    DWORD PTR [rbp-0x4],eax       ; acc += i
     401132: add    DWORD PTR [rbp-0x8],0x1       ; i++
     401136: mov    eax,DWORD PTR [rbp-0x8]       ; evaluasi: eax = i
     401139: cmp    eax,DWORD PTR [rbp-0xc]       ; bandingkan i dengan limit
     40113c: jl     40112c <main+0x26>            ; jika i < limit, ulangi loop
     40113e: mov    eax,DWORD PTR [rbp-0x4]       ; eax = acc
     401141: pop    rbp
     401142: ret
   ```
3. **Analisis Matematis Deterministik:**
   - Nilai awal akumulator: $acc_0 = 0x1e0da_{16} = 123098_{10}$.
   - Batas perulangan: $limit = 0x25f_{16} = 607_{10}$.
   - Rentang variabel pencacah: $i \in [0, 606]$.
   - Jumlah deret aritmatika Gauss untuk indeks $i$:
     $$\sum_{i=0}^{606} i = \frac{606 \times 607}{2} = 183921$$
   - Nilai akhir akumulator:
     $$acc_{\text{final}} = 123098 + 183921 = 307019$$
   - Baris `40113e: mov eax, DWORD PTR [rbp-0x4]` memuat nilai $307019$ ke dalam `eax` sebelum fungsi melakukan `ret`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh biner `debugger0_b` dari CDN CyLab:
   ```bash
   curl -sL https://challenge-files.cylabacademy.net/library/eea5e81c4ce7d6dcb85a3fe7d2edae4465705d230c68c45365cb9f24a69dfcf1/debugger0_b -o debugger0_b
   chmod +x debugger0_b
   ```
2. Analisis dinamis menggunakan GDB dengan menempatkan breakpoint tepat sebelum `ret`:
   - Alamat instruksi pemindahan hasil ke `eax`: `0x40113e`.
   - Pasang breakpoint pada epilog fungsi di `0x401141`:
   ```bash
   gdb -batch -ex "break *0x401141" -ex "run" -ex "info registers eax" debugger0_b
   ```
   Output GDB:
   ```text
   Breakpoint 1, 0x0000000000401141 in main ()
   eax            0x4af4b             307019
   ```
3. Nilai register `eax` dalam basis desimal terkonfirmasi $307019$.
4. Validasi konsistensi melalui skrip reproduktif `scripts/solve_396_gdb_baby_step_2.py`.
5. Kirim submisi flag ke endpoint REST API: `POST /api/submissions/` dengan payload `{"challenge": 396, "flag": "academy{307019}"}`.

---

## Flag & Verifikasi

- **Flag:** `academy{307019}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan HTTP Status `201 Created`:
  ```json
  {"user": 1072359, "challenge": 396, "flag": "academy{307019}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Penerapan teknik dynamic instrumentation melalui GDB breakpoints untuk menginspeksi status memori dan register runtime tanpa harus menguraikan seluruh siklus perulangan secara manual.
  - Pengenalan translasi compiler untuk struktur perulangan `for/while` serta formulasi deret aritmetika untuk verifikasi statis yang cepat.
- **Mitigasi Defensif:**
  - Optimasi kompiler tingkat `-O2` atau `-O3` secara otomatis melakukan *loop unrolling* atau *closed-form algebraic folding* (mengganti loop dengan rumus deret instan), yang mengabstraksi struktur kontrol dari pembacaan sekuensial langsung.
