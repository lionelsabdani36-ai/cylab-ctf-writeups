# Writeup: GDB baby step 4 (Challenge ID: 398)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Function Call Tracing & Multiplication Factor Recovery
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{12905}`

---

## Problem Statement & Scope

Diberikan sebuah berkas biner Linux ELF 64-bit bernama `debugger0_d`. Pada program ini, fungsi `main` memanggil sebuah sub-fungsi bernama `func1` yang mengalikan nilai integer dalam register `eax` dengan sebuah konstanta numerik. Peserta diminta mengidentifikasi nilai konstanta pengali tersebut melalui analisis statis disassembly atau debugging dinamis GDB, lalu mengonversinya ke basis bilangan desimal untuk membentuk flag `academy{n}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Konvensi Pemanggilan Fungsi (System V AMD64 Calling Convention):**
   - Pada arsitektur x86_64 Linux, argumen integer pertama yang dikirim ke fungsi diletakkan pada register `rdi` (atau versi 32-bit `edi`).
   - Nilai kembalian fungsi (*return value*) dikembalikan melalui register `rax` (atau `eax`).
2. **Dekomposisi Instruksi Disassembly Fungsi `main` & `func1`:**
   ```asm
   0000000000401106 <func1>:
     401106: endbr64 
     40110a: push   rbp
     40110b: mov    rbp,rsp
     40110e: mov    DWORD PTR [rbp-0x4],edi         ; simpan argumen pertama
     401111: mov    eax,DWORD PTR [rbp-0x4]         ; muat argumen ke eax
     401114: 69 c0 69 32 00 00  imul eax,eax,0x3269 ; eax = eax * 0x3269
     40111a: pop    rbp
     40111b: ret

   000000000040111c <main>:
     40111c: endbr64 
     401120: push   rbp
     401121: mov    rbp,rsp
     401124: sub    rsp,0x20
     401128: mov    DWORD PTR [rbp-0x14],edi
     40112b: mov    QWORD PTR [rbp-0x20],rsi
     40112f: mov    DWORD PTR [rbp-0x4],0x28e       ; inisialisasi variabel 0x28e (654)
     401136: mov    DWORD PTR [rbp-0x8],0x0
     40113d: mov    eax,DWORD PTR [rbp-0x4]
     401140: mov    edi,eax                         ; kirim sebagai argumen ke func1
     401142: call   401106 <func1>                  ; panggil func1
     401147: mov    DWORD PTR [rbp-0x8],eax         ; simpan hasil perkalian
     40114a: mov    eax,DWORD PTR [rbp-0x4]
     40114d: leave
     40114e: ret
   ```
3. **Analisis Operasi Perkaitan `imul`:**
   - Instruksi `imul dest, src, imm` melakukan perkalian bertanda antara register sumber dan konstanta langsung (*immediate value*), lalu menyimpan hasilnya ke register tujuan.
   - Pada baris `401114`, operan langsung adalah $0x3269_{16}$.
4. **Konversi Heksadesimal ke Desimal:**
   - $0x3269_{16} = (3 \times 16^3) + (2 \times 16^2) + (6 \times 16^1) + (9 \times 16^0)$
   - $= (3 \times 4096) + (2 \times 256) + 96 + 9 = 12288 + 512 + 96 + 9 = 12905_{10}$.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh berkas biner `debugger0_d` dari repository/CDN CyLab:
   ```bash
   curl -sL https://challenge-files.cylabacademy.net/library/5c4fe0af7766d02123d4ebea4a32b3b461fc6c5947049092d61d47518f298068/debugger0_d -o debugger0_d
   chmod +x debugger0_d
   ```
2. Telusuri simbol fungsi pada biner menggunakan `objdump`:
   ```bash
   objdump -d -M intel debugger0_d | grep -A 10 "<func1>:"
   ```
   Output:
   ```text
   0000000000401106 <func1>:
     401106:	f3 0f 1e fa          	endbr64 
     40110a:	55                   	push   rbp
     40110b:	48 89 e5             	mov    rbp,rsp
     40110e:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
     401111:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
     401114:	69 c0 69 32 00 00    	imul   eax,eax,0x3269
     40111a:	5d                   	pop    rbp
     40111b:	c3                   	ret
   ```
3. Alternatif pemeriksaan interaktif melalui GDB:
   ```bash
   gdb -batch -ex "file debugger0_d" -ex "disassemble func1"
   ```
4. Ekstraksi konstanta `0x3269` dan konversi ke bilangan desimal dalam Python:
   ```python
   int("0x3269", 16) # Output: 12905
   ```
5. Format flag akhir: `academy{12905}`.
6. Validasi solusi dengan skrip `scripts/solve_398_gdb_baby_step_4.py`.
7. Kirim submisi token flag ke endpoint REST API: `POST /api/submissions/` dengan payload `{"challenge": 398, "flag": "academy{12905}"}`.

---

## Flag & Verifikasi

- **Flag:** `academy{12905}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan HTTP Status `201 Created`:
  ```json
  {"user": 1072359, "challenge": 398, "flag": "academy{12905}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemampuan melacak alur *inter-procedural control flow* (pemanggilan sub-fungsi) melalui instruksi `call` dan konvensi register ABI.
  - Pemahaman terhadap optimasi aritmetika tingkat rendah, di mana kompiler sering mengganti instruksi perkalian `imul` dengan kombinasi instruksi bitwise shift (`shl`) dan penjumlahan (`lea`) bila faktor pengali merupakan bilangan berpangkat dua atau kombinasinya.
- **Mitigasi Defensif:**
  - Dalam kalkulasi numerik sensitif (seperti alokasi ukuran heap atau penghitungan saldo), pastikan operasi perkalian integer terlindung dari kerentanan *integer overflow* dengan menggunakan tipe data berukuran cukup (`size_t` / `uint64_t`) atau fungsi pengecekan intrinsik kompiler (`__builtin_mul_overflow`).
