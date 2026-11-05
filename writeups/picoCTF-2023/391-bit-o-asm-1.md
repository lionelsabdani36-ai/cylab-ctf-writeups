# Writeup: Bit-O-Asm-1 (Challenge ID: 391)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / x86_64 Assembly Tracing
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{48}`

---

## Problem Statement & Scope

Diberikan sebuah dump instruksi perakitan (assembly dump) arsitektur x86_64 bernama `disassembler-dump0_a.txt`. Peserta diminta menganalisis alur instruksi mesin dan menentukan nilai akhir yang tersimpan di dalam register `eax` pada akhir eksekusi fungsi, kemudian mengonversinya ke format desimal sesuai standar flag `academy{n}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **System V AMD64 ABI & Calling Conventions (NIST SP 800-115 Static Analysis):**
   - Pada arsitektur x86_64 dengan konvensi pemanggilan System V AMD64 ABI, register `rax` (dan sub-register 32-bit-nya `eax`) digunakan secara standar sebagai register penyimpan nilai balik (*return value*) dari suatu fungsi perakitan.
2. **Prolog & Epilog Fungsi:**
   - `<+0>: endbr64`: Penanda Indirect Branch Tracking (CET) untuk perlindungan Control-Flow Enforcement.
   - `<+4>: push rbp` & `<+5>: mov rbp, rsp`: Penataan stack frame fungsi (*standard function prologue*).
   - `<+20>: pop rbp` & `<+21>: ret`: Pemulihan frame pointer dan pengembalian alur eksekusi ke pemanggil (*function epilogue*).
3. **Analisis Instruksi Data Movement:**
   - `<+8>: mov DWORD PTR [rbp-0x4], edi`: Menyimpan argumen pertama (32-bit) ke stack lokal.
   - `<+11>: mov QWORD PTR [rbp-0x10], rsi`: Menyimpan argumen kedua (64-bit pointer) ke stack lokal.
   - `<+15>: mov eax, 0x30`: Memindahkan nilai langsung (*immediate constant*) `0x30` ke dalam register `eax`.
   - Tidak ada instruksi aritmatika lanjutan sebelum fungsi mengembalikan nilai via `ret`, sehingga register `eax` memegang nilai `0x30`.
4. **Konversi Bilangan Heksadesimal ke Desimal:**
   - $0x30_{16} = (3 \times 16^1) + (0 \times 16^0) = 48_{10}$.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh dump disassembler dari CDN resmi:
   ```bash
   curl -s https://challenge-files.cylabacademy.net/library/f24a79de39123fb31928d2d4baf2de2385e587d089b95005083051f9afb90fa9/disassembler-dump0_a.txt
   ```
2. Telaah isi instruksi yang diperoleh:
   ```asm
   <+0>:     endbr64 
   <+4>:     push   rbp
   <+5>:     mov    rbp,rsp
   <+8>:     mov    DWORD PTR [rbp-0x4],edi
   <+11>:    mov    QWORD PTR [rbp-0x10],rsi
   <+15>:    mov    eax,0x30
   <+20>:    pop    rbp
   <+21>:    ret
   ```
3. Identifikasi baris penentu nilai `eax`: `<+15>: mov eax,0x30`.
4. Konversi konstanta `0x30` ke desimal: $48$.
5. Jalankan verifikasi otomatis melalui skrip `scripts/solve_391_bit_o_asm_1.py`.
6. Submit flag ke REST API platform CyLab: `POST /api/submissions/` dengan payload `{"challenge": 391, "flag": "academy{48}"}`.

---

## Flag & Verifikasi

- **Flag:** `academy{48}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan HTTP Status `201 Created`:
  ```json
  {"user": 1072359, "challenge": 391, "flag": "academy{48}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Pengenalan dasar notasi Intel assembly, pembacaan register serbaguna x86_64, serta isolasi baris penugasan (*immediate-to-register assignment*).
  - Fondasi penting sebelum menghadapi tantangan reverse engineering biner yang lebih kompleks (seperti tracing loop, kontrol alur percabangan `cmp`/`jne`, dan dereferensi pointer).
- **Mitigasi Defensif:**
  - Pada lingkungan produksi, hindari meninggalkan konstanta diagnostik atau *magic values* yang transparan dalam biner unstripped; terapkan compiler optimization (`-O2` / `-O3`) dan stripping simbol (`strip --strip-all`) untuk mengurangi jejak statis yang mudah dibaca oleh analis biner.
