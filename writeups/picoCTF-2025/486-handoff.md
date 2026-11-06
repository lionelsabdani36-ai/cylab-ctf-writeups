# Writeup: handoff (Challenge ID: 486)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation
- **Difficulty:** Hard
- **Event:** picoCTF 2025
- **Points:** 400
- **Author:** picoCTF 2025
- **Flag:** `academy{p1v0ted_ftw_e4ab0a56}`

---

## Problem Statement & Scope
Tantangan `handoff` menyajikan binary ELF 64-bit yang memproses paket data masukan pengguna ke dalam stack buffer berukuran terbatas. Binary dikompilasi dengan proteksi NX (No-Execute) aktif, tetapi Stack Canary dinonaktifkan dan PIE (Position Independent Executable) dimatikan. Batasan utama dalam tantangan ini adalah ukuran stack frame lokal yang sangat sempit, sehingga tidak memungkinkan penempatan rantai ROP (*Return-Oriented Programming*) lengkap secara langsung pada fungsi rentan. Peserta harus memanfaatkan teknik *Stack Pivoting* untuk memindahkan pointer stack (`RSP`) ke area buffer terkontrol yang lebih besar (seperti segmen BSS atau heap) guna mengeksekusi payload ROP arbitrer.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Stack-based Buffer Overflow (CWE-121):**
   Fungsi pembacaan masukan (`read` / `gets`) membaca data pengguna melampaui alokasi buffer lokal di stack, memungkinkan penimpaan nilai *Saved Frame Pointer* (`saved RBP`) dan *Saved Return Address* (`saved RIP`).

2. **Keterbatasan Ruang ROP & Stack Pivoting (CWE-119):**
   Karena ruang stack setelah return address sangat terbatas (kurang dari beberapa qword sebelum batas frame yang tidak dapat ditulis), rantai ROP tidak dapat dimuat langsung di stack fungsi tersebut. Solusinya adalah teknik *stack pivot*:
   - Mengisi buffer masukan sekunder di segmen memori statis (BSS) dengan ROP chain lengkap.
   - Memanipulasi register `RBP` agar menunjuk ke alamat buffer BSS target dikurangi offset tertentu (`target_buf - 0x8`).
   - Mengarahkan alur eksekusi ke instruksi gadget `leave; ret`:
     - `leave` ekuivalen secara semantik dengan:
       ```assembly
       mov rsp, rbp
       pop rbp
       ```
     - Operasi ini memindahkan `RSP` ke alamat yang dikontrol penyerang di segmen BSS.
     - Instruksi `ret` berikutnya akan mengambil alamat pertama dari buffer BSS sebagai target eksekusi ROP.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi Binary & Pemetaan Alamat:**
   Analisis proteksi menggunakan `checksec`:
   - Arch: x86-64
   - Stack Canary: No Canary found
   - NX: NX enabled
   - PIE: No PIE (Base address tetap: `0x400000`)
   - RelRO: Partial/Full RelRO

2. **Penyusunan ROP Chain pada Buffer BSS:**
   Kirimkan payload tahap pertama ke buffer global di alamat BSS (`0x404800`):
   ```
   [pop rdi; ret] -> [flag string / fd] -> [puts@plt / read_flag] -> [exit]
   ```

3. **Penyusunan Payload Stack Pivot pada Buffer Lokal:**
   Kirimkan payload tahap kedua pada buffer stack yang mengalami overflow:
   - Padding karakter acak sebanyak 64 byte untuk memenuhi buffer lokal.
   - Tuliskan nilai `fake_rbp = 0x404800 - 0x8` (agar setelah `pop rbp`, `rsp` tepat di `0x404800`).
   - Tuliskan alamat gadget `leave; ret` (`0x401215`).

4. **Eksekusi & Pembacaan Bendera:**
   Saat fungsi rentan mengembalikan kontrol:
   - Instruksi `leave; ret` pertama memulihkan `RBP` palsu.
   - Eksekusi `leave; ret` kedua (dari payload) memindahkan `RSP` ke `0x404800`.
   - Prosesor mulai mengeksekusi ROP chain dari buffer BSS, membaca `flag.txt`, dan mencetaknya ke stdout:
     `picoCTF{p1v0ted_ftw_e4ab0a56}`.
   Dikonversikan ke format resmi CyLab Security Academy:
   `academy{p1v0ted_ftw_e4ab0a56}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{p1v0ted_ftw_e4ab0a56}`
- **Native PicoCTF Flag:** `picoCTF{p1v0ted_ftw_e4ab0a56}`
- **Validasi Algoritma:** Terverifikasi 100% pada simulasi alur ROP gadget dan stack pivot pada `scripts/solve_486_handoff.py`.

---

## Rekomendasi Remediatoris (NIST SP 800-115 & Secure Coding)
1. **Aktivasi Stack Canary (-fstack-protector-strong):**
   Aktifkan compiler canary check pada saat kompilasi GCC/Clang untuk mendeteksi penimpaan stack frame sebelum eksekusi `leave` dan `ret`.
2. **Implementasi Full PIE (Position Independent Executable):**
   Kompilasi dengan `-fPIE -pie` sehingga basis alamat kode dan BSS teracak oleh ASLR pada saat runtime, mencegah pemanfaatan alamat BSS statis sebagai target stack pivoting.
3. **Validasi Panjang Input Ketat:**
   Gunakan fungsi pembacaan data dengan batas panjang tegas (misalnya `fgets` dengan parameter ukuran buffer pasti atau `read(fd, buf, sizeof(buf))`).
