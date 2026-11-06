# Writeup: ARMssembly 0 (Challenge ID: 160)

- Platform: CyLab Security Academy (picoCTF)
- Category: Reverse Engineering / AArch64 Assembly Analysis
- Difficulty: Medium (diff=2)
- Author: Dylan McGuire
- Event: picoCTF 2021
- Points: 40
- Flag: `academy{e99c9e31}` (Komunitas: `CTF{e99c9e31}`)

---

## Problem Statement & Scope

Tantangan menguji kemampuan dekomposisi instruksi bahasa assembly arsitektur ARM 64-bit (AArch64) dan rekonstruksi alur eksekusi logika percabangan:
> *"What integer does this program print?*  
> *Flag format: academy{XXXXXXXX} -> (hex, lowercase, no 0x, and 32 bits. ex. 5614267 would be academy{0055aabb})*  
> *Use arguments a and b: 2432642318 and 3919355441*  
> *File: chall.S"*  
>  
> Petunjuk:  
> *"Simple compare"*

Lingkup pengujian mencakup audit statis terhadap berkas assembly GNU syntax (`chall.S`), pemetaan konvensi pemanggilan fungsi AArch64 ABI (Application Binary Interface), analisis pemrosesan tipe data signed vs unsigned pada instruksi `cmp` dan `bls`, serta konversi nilai luaran komputasi ke representasi heksadesimal 32-bit.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Konvensi Register & ABI AArch64 (ARMv8-A Architecture):**
   - Register `x0` - `x7` digunakan untuk melewatkan argumen fungsi dan nilai kembalian (*return value*).
   - Register `w0` - `w30` merepresentasikan 32-bit bagian bawah (*lower 32-bit word*) dari register 64-bit `x0` - `x30`.
   - Pada fungsi `main`, masukan baris perintah `argv[1]` dan `argv[2]` dikonversi menjadi representasi integer 32-bit melalui pemanggilan fungsi library C `atoi()`. Hasil konversi diteruskan ke register `w0` (argumen $a$) dan `w1` (argumen $b$) sebelum memanggil subrutin `func1`.

2. **Semantik Komparasi & Percabangan Kondisional (CWE-682):**
   - Perhatikan instruksi inti pada `func1`:
     ```armasm
     func1:
         sub sp, sp, #16
         str w0, [sp, 12]   ; Simpan argumen a pada stack frame
         str w1, [sp, 8]    ; Simpan argumen b pada stack frame
         ldr w1, [sp, 12]   ; w1 = a
         ldr w0, [sp, 8]    ; w0 = b
         cmp w1, w0         ; Bandingkan w1 (a) dengan w0 (b)
         bls .L2            ; Branch if Lower or Same (unsigned a <= b)
         ldr w0, [sp, 12]   ; Mengembalikan a (jika a > b)
         b .L3
     .L2:
         ldr w0, [sp, 8]    ; Mengembalikan b (jika a <= b)
     .L3:
         add sp, sp, 16
         ret
     ```
   - Mnemonic `bls` (*Branch if Lower or Same*) mengevaluasi flag status prosesor PSTATE ($C = 0 \text{ atau } Z = 1$), yang beroperasi secara *unsigned*.
   - Oleh karena itu, fungsi `func1(a, b)` mengimplementasikan fungsi matematika $\max_{\text{unsigned}}(a, b)$. Kesalahan umum peserta CTF/LKS adalah memperlakukan perbandingan ini sebagai perbandingan bertanda (*signed compare* / `ble`) atau membalikkan prioritas operan register.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Argumen Masukan:**
   Diberikan dua nilai masukan:
   - Argumen $a = 2432642318$
   - Argumen $b = 3919355441$

2. **Evaluasi Percabangan Kondisional:**
   Dalam aritmatika integer unsigned 32-bit:
   - $a = 2432642318 = \text{0x90FF2D0E}$
   - $b = 3919355441 = \text{0xE99C9E31}$
   - Evaluasi $a \le b$: Karena $2432642318 < 3919355441$, instruksi `cmp w1, w0; bls .L2` terpenuhi ($C=0$).
   - Eksekusi melompat ke label `.L2`, memuat nilai $b$ ke register `w0`, dan kembali ke fungsi pemanggil `main`.
   - Luaran `printf("Result: %ld\n", result)` mencetak nilai $3919355441$.

3. **Format Flag 32-Bit Hexadecimal:**
   Mengubah nilai integer kembalian ke dalam format heksadesimal huruf kecil 8 digit tanpa prefiks `0x`:
   $$\text{hex}(3919355441) = \text{e99c9e31}$$
   Sesuai spesifikasi template, flag dibentuk sebagai:
   $$\text{academy}\{\text{e99c9e31}\}$$

4. **Verifikasi Otomasi Python:**
   Skrip reproduktif dieksekusi melalui `scripts/solve_160_armssembly_0.py`:
   ```bash
   python3 scripts/solve_160_armssembly_0.py
   # Luaran: academy{e99c9e31}
   ```

---

## Flag & Verifikasi

- **Flag:** `academy{e99c9e31}`
- **Komunitas:** `CTF{e99c9e31}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 160, "flag": "academy{e99c9e31}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi Reversing Multi-Arsitektur pada LKS Cyber Security:**
   - Peserta LKS Nasional dituntut tidak hanya menguasai x86/x86_64, tetapi juga arsitektur RISC modern seperti ARM64 (AArch64) dan MIPS/RISC-V yang mendominasi perangkat IoT, mobile, dan cloud server.
   - Pahami pemetaan flag PSTATE/EFLAGS: `bls`/`bhi` untuk unsigned integer, dan `ble`/`bgt` untuk signed integer. Kesalahan pembacaan mnemonic kondisional dapat memicu salah diagnosis jalur eksekusi malware atau algoritma kriptografi.

2. **Rekomendasi Pemrograman Defensif (Remediation & Hardening):**
   - **Gunakan Tipe Data Eksplisit:** Hindari pencampuran tipe bertanda (`int`) dari `atoi()` dengan perbandingan tidak bertanda (`unsigned int`). Gunakan fungsi `strtoul()` dengan penanganan galat `errno` untuk memastikan batas validasi input bilangan bulat positif yang ketat.
   - **Kompilasi dengan Flag Pengaman:** Aktifkan `-Wsign-compare` dan `-Wconversion` pada GCC/Clang untuk mendeteksi secara otomatis potensi pergeseran tipe signed-to-unsigned pada fase *build time*.
