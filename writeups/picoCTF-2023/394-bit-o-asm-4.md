# Writeup: Bit-O-Asm-4 (Challenge ID: 394)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / x86_64 Conditional Branching & Subtraction Tracing
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{654773}`

---

## Problem Statement & Scope

Diberikan sebuah berkas disassembler dump x86_64 bernama `disassembler-dump0_d.txt`. Peserta diminta menganalisis instruksi komparasi bersyarat (`cmp`), percabangan berbasis flag status prosesor (`jle`), serta operasi aritmatika pengurangan (`sub`) dan lompatan tanpa syarat (`jmp`) untuk menentukan nilai desimal akhir di dalam register akumulator `eax`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Analisis Percabangan Bersyarat x86_64 (NIST SP 800-115 Static Analysis):**
   - Pola kontrol alur tingkat tinggi tipe `if-else` dikompilasi ke dalam perakitan menggunakan kombinasi instruksi perbandingan dan lompatan bersyarat (*conditional branch*).
   - Instruksi `cmp op1, op2` mengeksekusi operasi aritmetika internal $op1 - op2$ tanpa mengubah nilai operan, melainkan memperbarui register status *EFLAGS* (khususnya Sign Flag `SF`, Zero Flag `ZF`, dan Overflow Flag `OF`).
2. **Semantik Lompatan `jle` (Jump if Less or Equal):**
   - Pada perbandingan bertanda (*signed comparison*), `jle` (atau `jng` - *Jump if Not Greater*) melompat ke alamat target jika dan hanya jika:
     $$\text{ZF} = 1 \quad \lor \quad (\text{SF} \ne \text{OF})$$
   - Secara intuitif, cabang diambil jika operan pertama lebih kecil atau sama dengan operan kedua ($op1 \le op2$).
3. **Dekonstruksi Alur Eksekusi Instruksi:**
   ```asm
   <+0>:     endbr64 
   <+4>:     push   rbp
   <+5>:     mov    rbp,rsp
   <+8>:     mov    DWORD PTR [rbp-0x14],edi
   <+11>:    mov    QWORD PTR [rbp-0x20],rsi
   <+15>:    mov    DWORD PTR [rbp-0x4],0x9fe1a
   <+22>:    cmp    DWORD PTR [rbp-0x4],0x2710
   <+29>:    jle    0x55555555514e <main+37>
   <+31>:    sub    DWORD PTR [rbp-0x4],0x65
   <+35>:    jmp    0x555555555152 <main+41>
   <+37>:    add    DWORD PTR [rbp-0x4],0x65
   <+41>:    mov    eax,DWORD PTR [rbp-0x4]
   <+44>:    pop    rbp
   <+45>:    ret
   ```
4. **Tracing Logika Komputasi:**
   - Baris `<+15>`: Variabel stack lokal `[rbp-0x4]` diinisialisasi dengan nilai heksadesimal $0x9fe1a_{16} = 654874_{10}$.
   - Baris `<+22>`: Komparasi terhadap konstanta $0x2710_{16} = 10000_{10}$.
   - Baris `<+29>`: Evaluasi kondisi $654874 \le 10000$. Kondisi bernilai **salah** (*False*), sehingga percabangan `jle` tidak dieksekusi (fall-through).
   - Baris `<+31>`: Pengurangan nilai lokal dengan konstanta $0x65_{16} = 101_{10}$:
     $$\text{hasil} = 654874 - 101 = 654773$$
   - Baris `<+35>`: Lompatan tanpa syarat `jmp` langsung menuju `<main+41>`, melewati instruksi `add` pada `<+37>`.
   - Baris `<+41>`: Nilai $654773$ dari memori dimuat ke register `eax` sebagai nilai kembalian fungsi.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh dump disassembler resmi:
   ```bash
   curl -s https://challenge-files.cylabacademy.net/library/b14a53c80d0f28fa842055ab567694917ef71b9f466545c3597aa8940284e212/disassembler-dump0_d.txt
   ```
2. Analisis blok perbandingan dan evaluasi percabangan:
   - Nilai awal: `0x9fe1a` (654874)
   - Pembanding: `0x2710` (10000)
   - Evaluasi relasi: `654874 <= 10000` adalah False.
3. Jalankan cabang yang aktif:
   - Operasi `sub`: `654874 - 0x65 = 654874 - 101 = 654773`.
4. Jalankan script solver otomatis `scripts/solve_394_bit_o_asm_4.py` untuk mengonfirmasi hasil parsing dan kalkulasi.
5. Kirim submisi flag ke endpoint REST API: `POST /api/submissions/` dengan payload `{"challenge": 394, "flag": "academy{654773}"}`.

---

## Flag & Verifikasi

- **Flag:** `academy{654773}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan HTTP Status `201 Created`:
  ```json
  {"user": 1072359, "challenge": 394, "flag": "academy{654773}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemampuan memetakan alur kontrol bersyarat (*control flow graph / CFG*) dari assembly disassembly mentah.
  - Memahami korelasi antara instruksi komparasi `cmp` dan bendera status `EFLAGS` dalam menentukan jalur eksekusi `if/else` tanpa bantuan dekompiler tingkat tinggi (seperti Ghidra atau IDA Pro).
- **Mitigasi Defensif:**
  - Dalam perancangan kode keamanan kritis (seperti verifikasi kata sandi atau validasi token kriptografis), hindari percabangan bersyarat yang rentan terhadap serangan analisis waktu (*timing attacks*). Gunakan perbandingan konstan waktu (*constant-time comparison*) untuk mencegah penyerang mengukur perbedaan waktu eksekusi antar cabang.
