# Writeup: Binary Gauntlet 3 (Challenge ID: 133)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Stack Shellcode & Blind Format String Leak
- **Difficulty:** Medium
- **Event:** picoCTF 2021
- **Points:** 50
- **Author:** picoCTF
- **Flag:** `academy{gauntlet3_fmt_str_stk_sh3ll_133}`

---

## Problem Statement & Scope
Diberikan biner ELF x86-64 `gauntlet` yang dieksekusi secara interaktif melalui socket remote TCP. Berbeda dengan Binary Gauntlet 1 dan 2 yang mencetak bocoran alamat stack di banner secara otomatis, tantangan ini tidak memberikan banner leak eksplisit. Peserta harus membocorkan tata letak memori stack secara mandiri dalam satu koneksi persisten dan membajak kontrol instruksi RIP.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Uncontrolled Format String Vulnerability (CWE-134):**
   Program membaca baris pertama ke dalam buffer heap dan mengeksekusi `printf(buf)` tanpa format specifier statis. Celah ini memungkinkan penyerang mengirimkan deretan `%p` untuk menginspeksi alamat-alamat register dan stack frame secara real-time.
2. **Unbounded String Copy Buffer Overflow (CWE-121):**
   Pada baris kedua, program memanggil `strcpy(stack_buf, buf)` di mana `stack_buf` hanya berukuran 112 byte di frame stack fungsi `vuln()`. Karena `strcpy` tidak membatasi panjang input, kelebihan byte akan menimpa saved RBP dan saved RIP (pada offset 120 byte).
3. **Executable Stack (`GNU_STACK RWE`):**
   Biner dikompilasi tanpa perlindungan NX (*No-Execute*), sehingga kode mesin shellcode yang ditempatkan langsung di stack dapat dieksekusi oleh CPU saat RIP diarahkan ke stack.
4. **NUL-Byte Preservation pada Alamat Stack x86-64:**
   Meskipun fungsi `strcpy` berhenti saat menemukan karakter `\x00` (NUL byte), alamat stack pengguna (`0x7ffd...` / `0x7ffe...`) hanya memiliki byte NUL pada posisi byte tertinggi (trailing bytes). Karena arsitektur little-endian dan sisa frame yang sudah bernilai `0x00`, penulisan 6 byte alamat stack efektif berhasil merekonstruksi pointer RIP secara utuh.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Mitigasi Biner:**
   ```bash
   checksec gauntlet
   # NX: Disabled (Stack Executable)
   # PIE: No PIE (Base 0x400000)
   # Canary: No Canary found
   ```
2. **Blind Stack Leak via Format String:**
   Pada masukan baris pertama, kirim string specifier format:
   ```text
   START.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p...
   ```
   Server merespons dengan deretan alamat heksadesimal. Filter nilai stack yang diawali `0x7ffd...` atau `0x7ffe...` untuk mengidentifikasi kluster frame stack lokal dan mengestimasi alamat basis buffer `buf`.
3. **Penyusunan Payload Shellcode & Hijack RIP:**
   - Masukan baris kedua disusun dengan skema:
     - 8 byte padding sampah
     - 8 byte alamat target eksekusi shellcode (`buf + 16`)
     - 27 byte null-free & newline-free `execve("/bin/sh")` shellcode
     - NOP sled dan padding hingga offset 112 byte
     - Overwrite saved RBP (`buf`)
     - Overwrite saved RIP (`buf`)
4. **Pemicu Eksekusi (`leave; ret`):**
   Saat fungsi mengakhiri frame:
   - Instruksi `leave` menyetel `RSP = RBP = buf` dan mem-pop RBP.
   - Instruksi `ret` mengambil nilai di puncak stack baru (`buf + 16`) dan melompat langsung mengeksekusi shellcode.
5. **Ekstraksi Flag:**
   Melalui koneksi shell yang terbuka, kirim perintah `cat flag.txt` untuk membaca token rahasia resmi: `academy{gauntlet3_fmt_str_stk_sh3ll_133}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{gauntlet3_fmt_str_stk_sh3ll_133}`
- **Status Solver:** Terverifikasi melalui skrip pengujian reproduktif `scripts/solve_133_binary_gauntlet_3.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Modern Binary Mitigations (W^X):**
  Pastikan opsi kompilasi `-z noexecstack` aktif secara default untuk mencegah eksekusi kode di segmen stack data.
- **Format String Sanitization:**
  Selalu gunakan format string literal yang ketat: `printf("%s", buf)` dan aktifkan flag `-Wformat -Werror=format-security`.
- **Penggantian Fungsi Rawan:**
  Migrasikan fungsi rawan buffer overflow seperti `strcpy` ke alternatif aman dengan pembatasan panjang eksplisit: `strlcpy` atau `strncpy` dengan null-terminator enforcement.
