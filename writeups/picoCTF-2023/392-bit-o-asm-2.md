# Writeup: Bit-O-Asm-2 (Challenge ID: 392)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / x86_64 Stack Memory Tracing
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{654874}`

---

## Problem Statement & Scope

Diberikan sebuah berkas disassembler dump x86_64 `disassembler-dump0_b.txt`. Peserta diminta menganalisis interaksi memori stack dan pergerakan data antar-register untuk menentukan nilai desimal akhir di dalam register `eax` saat fungsi berakhir.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Stack Memory Addressing & Local Variables (NIST SP 800-115 Static Analysis):**
   - Dalam kompilasi bahasa C tanpa optimasi (`-O0`), compiler mengalokasikan variabel lokal pada stack frame fungsi menggunakan base pointer `rbp`.
   - Alamat `[rbp - offset]` merepresentasikan slot variabel lokal di stack. Notasi `DWORD PTR` menunjukkan operasi baca/tulis memori sebesar 4 byte (32-bit integer).
2. **Analisis Alur Eksekusi Instruksi:**
   ```asm
   <+0>:     endbr64 
   <+4>:     push   rbp
   <+5>:     mov    rbp,rsp
   <+8>:     mov    DWORD PTR [rbp-0x14],edi
   <+11>:    mov    QWORD PTR [rbp-0x20],rsi
   <+15>:    mov    DWORD PTR [rbp-0x4],0x9fe1a
   <+22>:    mov    eax,DWORD PTR [rbp-0x4]
   <+25>:    pop    rbp
   <+26>:    ret
   ```
   - Pada baris `<+15>`, konstanta heksadesimal `0x9fe1a` disimpan ke slot stack frame lokal pada alamat `[rbp-0x4]`.
   - Pada baris `<+22>`, nilai 32-bit dari slot memori `[rbp-0x4]` dibaca kembali dan dimuat ke dalam register `eax`.
   - Karena tidak terdapat instruksi modifikasi lain sebelum `ret`, register `eax` mempertahankan nilai `0x9fe1a`.
3. **Konversi Basis Heksadesimal ke Desimal:**
   - $0x9fe1a_{16} = (9 \times 16^4) + (15 \times 16^3) + (14 \times 16^2) + (1 \times 16^1) + (10 \times 16^0)$
   - $= 589824 + 61440 + 3584 + 16 + 10 = 654874_{10}$.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh dump disassembler:
   ```bash
   curl -s https://challenge-files.cylabacademy.net/library/0325d59cb3b29a78bb7872b19f37856d51973b33085362dd4fe5f4cbe7aef80c/disassembler-dump0_b.txt
   ```
2. Analisis baris perakitan yang memanipulasi `eax`:
   - Penulisan ke memori lokal: `mov DWORD PTR [rbp-0x4], 0x9fe1a`
   - Pembacaan dari memori lokal: `mov eax, DWORD PTR [rbp-0x4]`
3. Evaluasi nilai heksadesimal `0x9fe1a` ke format desimal:
   ```python
   int("0x9fe1a", 16) # Output: 654874
   ```
4. Verifikasi konsistensi menggunakan skrip otomatis `scripts/solve_392_bit_o_asm_2.py`.
5. Kirim submisi flag ke endpoint REST API: `POST /api/submissions/` dengan payload `{"challenge": 392, "flag": "academy{654874}"}`.

---

## Flag & Verifikasi

- **Flag:** `academy{654874}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status HTTP `201 Created`:
  ```json
  {"user": 1072359, "challenge": 392, "flag": "academy{654874}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Pemahaman terhadap *local variable lifecycle* pada stack frame x86_64, konvensi *dereferencing* `DWORD PTR`, serta alur transfer data tidak langsung (*indirect data transfer*) dari memori ke register.
- **Mitigasi Defensif:**
  - Kompiler modern dengan tingkat optimasi standar (`-O2`) akan mengeliminasi *redundant store-and-load* semacam ini melalui teknik *constant propagation* dan *dead store elimination*, meminimalkan jejak instruksi yang tidak efisien dalam binary release.
