# Writeup: Bit-O-Asm-3 (Challenge ID: 393)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / x86_64 Arithmetic & Register Tracing
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{2619997}`

---

## Problem Statement & Scope

Diberikan sebuah berkas disassembler dump x86_64 `disassembler-dump0_c.txt`. Peserta diminta menganalisis eksekusi instruksi aritmatika berurutan (perkalian dan penambahan integer) pada register dan memori stack, untuk menentukan nilai desimal akhir di dalam register `eax`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Rangkaian Operasi Aritmatika Perakitan (NIST SP 800-115 Static Analysis):**
   - Berbeda dari dua tantangan sebelumnya yang hanya memuat penugasan nilai (*pure data movement*), tantangan ini memperkenalkan instruksi manipulasi aritmatika integer:
     - `imul dest, src`: Mengalikan nilai pada register `dest` dengan operan sumber `src`.
     - `add dest, imm`: Menambahkan nilai langsung `imm` ke register tujuan `dest`.
2. **Dekonstruksi Alur Eksekusi Instruksi:**
   ```asm
   <+0>:     endbr64 
   <+4>:     push   rbp
   <+5>:     mov    rbp,rsp
   <+8>:     mov    DWORD PTR [rbp-0x14],edi
   <+11>:    mov    QWORD PTR [rbp-0x20],rsi
   <+15>:    mov    DWORD PTR [rbp-0xc],0x9fe1a
   <+22>:    mov    DWORD PTR [rbp-0x8],0x4
   <+29>:    mov    eax,DWORD PTR [rbp-0xc]
   <+32>:    imul   eax,DWORD PTR [rbp-0x8]
   <+36>:    add    eax,0x1f5
   <+41>:    mov    DWORD PTR [rbp-0x4],eax
   <+44>:    mov    eax,DWORD PTR [rbp-0x4]
   <+47>:    pop    rbp
   <+48>:    ret
   ```
3. **Tracing Matematika:**
   - Baris `<+15>`: Menyimpan $0x9fe1a_{16} = 654874_{10}$ ke slot memori `[rbp-0xc]`.
   - Baris `<+22>`: Menyimpan $0x4_{16} = 4_{10}$ ke slot memori `[rbp-0x8]`.
   - Baris `<+29>`: Memuat nilai dari `[rbp-0xc]` ke register `eax` ($\text{eax} = 654874$).
   - Baris `<+32>`: Mengalikan `eax` dengan nilai di `[rbp-0x8]` ($\text{eax} = 654874 \times 4 = 2619496$).
   - Baris `<+36>`: Menambahkan konstanta $0x1f5_{16} = 501_{10}$ ke `eax` ($\text{eax} = 2619496 + 501 = 2619997$).
   - Baris `<+41>` & `<+44>`: Menyimpan dan memuat ulang nilai `2619997` ke `[rbp-0x4]`, menjaga nilai akhir `eax` tetap $2619997$.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh dump disassembler:
   ```bash
   curl -s https://challenge-files.cylabacademy.net/library/f16508f6e8ba4c520e7541081aee169bf4f5cab84d6852b697299b8cf4aff76a/disassembler-dump0_c.txt
   ```
2. Telusuri operasi perakitan secara berurutan:
   - $a = 0x9fe1a$
   - $b = 0x4$
   - $c = (a \times b) + 0x1f5$
3. Hitung nilai akhir dalam Python:
   ```python
   ans = (0x9fe1a * 0x4) + 0x1f5
   print(ans) # 2619997
   ```
4. Jalankan script solver otomatis `scripts/solve_393_bit_o_asm_3.py` untuk memvalidasi output.
5. Kirim submisi flag ke endpoint REST API: `POST /api/submissions/` dengan payload `{"challenge": 393, "flag": "academy{2619997}"}`.

---

## Flag & Verifikasi

- **Flag:** `academy{2619997}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status HTTP `201 Created`:
  ```json
  {"user": 1072359, "challenge": 393, "flag": "academy{2619997}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemampuan melacak kalkulasi aritmatika bertingkat pada assembly x86_64, pemahaman terhadap perkalian bertanda `imul` dan penambahan integer `add`, serta penanganan akumulator `eax`.
- **Mitigasi Defensif:**
  - Penggunaan compiler flags modern (`-O3`, `-fomit-frame-pointer`) akan menyederhanakan rangkaian instruksi menjadi satu pemuatan konstanta langsung atau kalkulasi register tanpa akses memori stack perantara yang boros siklus clock.
