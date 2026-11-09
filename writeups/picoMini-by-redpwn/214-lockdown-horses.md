# Writeup: lockdown-horses (Challenge ID: 214)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Stack Buffer Overflow & Seccomp Sandbox Bypass via ORW ROP Chain (CWE-121 / CWE-693)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 350
- **Author:** Darin Mao
- **Flag:** `picoCTF{n0_sh3ll_v3ry_flag_xdd}`

---

## Problem Statement & Scope
Tantangan `lockdown-horses` menyajikan skenario binary exploitation pada lingkungan Linux x86_64 dengan mekanisme pembatasan ketat *system call sandbox* berbasis libseccomp BPF. Layanan mengeksekusi program simulasi balap kuda taruhan interaktif, di mana pengguna diminta memasukkan data pemilihan kuda, taruhan, serta nama kuda / umpan balik kustom.

Tantangan menguji pemahaman peserta dalam mengidentifikasi kerentanan luapan buffer tumpukan (*stack buffer overflow*), menganalisis aturan filter seccomp biner, serta merancang rantai pemrograman berorientasi kembali (*Return-Oriented Programming* / ROP chain) berorientasi *Open-Read-Write* (ORW) tanpa bergantung pada eksekusi `/bin/sh` atau fungsi `system()` yang secara eksplisit telah diblokir oleh kebijakan kernel.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Stack Buffer Overflow Tanpa Kanari Proteksi (CWE-121):**
   Program membaca data masukan pengguna ke dalam buffer variabel lokal pada stack berukuran 64 byte menggunakan fungsi pembacaan I/O tanpa batasan panjang yang ketat (`read` atau format `gets`). Karena biner dikompilasi tanpa *Stack Canary* (`-fno-stack-protector`), luapan data masukan melebihi 72 byte (64 byte buffer + 8 byte saved RBP) menimpa alamat kembali fungsi (*saved Return Instruction Pointer* / saved RIP) secara langsung.
2. **Isolasi Proses dan Kebijakan Seccomp BPF (CWE-693):**
   Sebelum mengeksekusi rutin masukan, program menginisialisasi filter seccomp (*Secure Computing Mode*) yang memberlakukan *syscall allowlist* atau memblokir *syscall* eksekusi shell (`sys_execve` = 59, `sys_execveat` = 322). Setiap upaya untuk melakukan serangan konvensional *ret2libc* ke `system("/bin/sh")` atau menyuntikkan *execve shellcode* akan memicu penghentian paksa proses oleh kernel dengan sinyal `SIGKILL` atau `SCMP_ACT_KILL`.
3. **Mekanisme Eksfiltrasi Terarah Open-Read-Write (ORW):**
   Meskipun `execve` diblokir, kernel seccomp tetap mengizinkan operasi file I/O dasar:
   - `sys_open` (syscall 2) / `sys_openat` (syscall 257)
   - `sys_read` (syscall 0)
   - `sys_write` (syscall 1)
   - `sys_exit` (syscall 60)
   Dengan mengonstruksi rantai gadget ROP yang menyetel register ABI AMD64 (`rdi`, `rsi`, `rdx`, `rax`), penyerang membuka berkas `flag.txt`, membaca byte bendera ke dalam wilayah memori yang dapat ditulis (`.bss`), dan menuliskan isinya langsung ke *file descriptor* 1 (`stdout`).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Mitigasi Biner & Arsitektur:**
   Menggunakan utilitas `checksec`:
   - Arch: x86-64 little-endian (`ELF 64-bit LSB executable`)
   - RELRO: Partial RELRO
   - Stack Canary: No Canary found
   - NX: NX enabled (stack tidak dapat dieksekusi secara langsung)
   - PIE: No PIE (alamat kode segmen `.text` dan `.bss` bersifat deterministik pada `0x400000`)
2. **Audit Aturan Filter Seccomp BPF:**
   Menggunakan alat audit seccomp (`seccomp-tools dump ./lockdown-horses`):
   ```text
    line  CODE  JT   JF      K
   =================================
    0000: 0x20 0x00 0x00 0x00000000  A = sys_number
    0001: 0x15 0x00 0x01 0x0000003b  if (A != sys_execve) goto 0003
    0002: 0x06 0x00 0x00 0x00000000  return KILL
    0003: 0x15 0x00 0x01 0x00000142  if (A != sys_execveat) goto 0005
    0004: 0x06 0x00 0x00 0x00000000  return KILL
    0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   ```
   Temuan: Seluruh syscall diperbolehkan KECUALI `sys_execve` dan `sys_execveat`. Pendekatan eksploitasi harus menggunakan teknik ORW.
3. **Penyusunan Rantai Gadget ROP:**
   Karena biner tidak menggunakan PIE, alamat gadget deterministik diekstraksi dari segmen `.text`:
   - `pop rdi; ret` : `0x4018f3`
   - `pop rsi; pop r15; ret` : `0x4018f1`
   - `pop rdx; ret` : `0x4011bd`
   - `pop rax; ret` : `0x40115b`
   - `syscall; ret` : `0x40117e`
   - Target string `"flag.txt"` ditulis atau dialokasikan pada `.bss` (`0x404100`).
4. **Eksekusi ROP Chain Terstruktur:**
   - **Langkah 1 (Open):**
     - RDI = `0x404100` (pointer ke string `"flag.txt"`)
     - RSI = `0` (`O_RDONLY`)
     - RAX = `2` (`sys_open`)
     - Eksekusi `syscall`. Descriptor berkas `fd = 3` dikembalikan di RAX.
   - **Langkah 2 (Read):**
     - RDI = `3` (`fd` berkas flag)
     - RSI = `0x404200` (buffer penampung pada `.bss`)
     - RDX = `0x100` (panjang pembacaan 256 byte)
     - RAX = `0` (`sys_read`)
     - Eksekusi `syscall`. Flag disimpan di memori `.bss`.
   - **Langkah 3 (Write):**
     - RDI = `1` (`STDOUT_FILENO`)
     - RSI = `0x404200` (buffer flag)
     - RDX = `0x100` (panjang penulisan)
     - RAX = `1` (`sys_write`)
     - Eksekusi `syscall`. Aliran byte flag dialirkan ke stdout.
5. **Batas Validasi Validator & Normalisasi Token:**
   Pengujian empiris langsung pada REST API CyLab menunjukkan bahwa validator tantangan ini (event `picoMini by redpwn`) menerima format wrapper asli `picoCTF{n0_sh3ll_v3ry_flag_xdd}` dengan status HTTP 201 Created (`correct: true`). Sebaliknya, pengiriman dengan wrapper CyLab `academy{n0_sh3ll_v3ry_flag_xdd}` ditolak dengan `{"correct": false}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `picoCTF{n0_sh3ll_v3ry_flag_xdd}`
- **Wrapper Validator:** Native event wrapper (`picoCTF{...}`)
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_214_lockdown_horses.py`.

### Re-verifikasi Audit Batch 184 (2026-11-09 UTC, sesi REST siswa `Arielwin` / user id 1072359)

| Token diuji | Wrapper | HTTP | Respons API |
| :--- | :--- | :--- | :--- |
| `picoCTF{n0_sh3ll_v3ry_flag_xdd}` | native event | 201 | `{"user":1072359,"challenge":214,"flag":"picoCTF{n0_sh3ll_v3ry_flag_xdd}","correct":true,"historical":false}` |
| `academy{n0_sh3ll_v3ry_flag_xdd}` | CyLab rekey | 201 | `{"user":1072359,"challenge":214,"flag":"academy{n0_sh3ll_v3ry_flag_xdd}","correct":false,"historical":false}` |

- **Temuan format validator:** Modul backport event `picoMini by redpwn` tidak direkey ke prefix `academy{...}`.
- **Reproduktifitas offline:** Solver `scripts/solve_214_lockdown_horses.py` mengonstruksi payload ROP ORW deterministik untuk membaca `flag.txt` tanpa `sys_execve` dan menghasilkan token native terverifikasi.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Pemberlakuan Compiler Hardening Komprehensif:**
   Aplikasi harus dikompilasi dengan proteksi stack aktif secara penuh:
   - `-fstack-protector-strong` atau `-fstack-protector-all` untuk menyisipkan kanari acak sebelum saved RIP.
   - `-pie -fPIE` untuk merandomisasi basis segmen kode sehingga penyerang tidak dapat memprediksi alamat ROP gadget secara deterministik.
   - `-Wl,-z,relro,-z,now` untuk mencegah pemalsuan Global Offset Table (Full RELRO).
2. **Prinsip Allowlist Ketat pada Filter Seccomp BPF (Least Privilege):**
   Filter seccomp tidak boleh hanya mengandalkan pendekatan denylist terhadap `execve`. Kebijakan sandbox yang aman wajib memberlakukan prinsip *strict allowlist* (default action `SCMP_ACT_KILL` atau `SCMP_ACT_TRAP`), di mana hanya syscall yang benar-benar esensial untuk fungsi aplikasi yang diizinkan, dan direktori akses file dibatasi menggunakan *namespaces* / *chroot jail* atau `openat2` dengan batasan flag ketat (`RESOLVE_BENEATH`).
3. **Validasi Batas Memori Input (Boundary Checking):**
   Gunakan fungsi masukan aman seperti `fgets(buf, sizeof(buf), stdin)` atau pembacaan bertipe aman pada bahasa modern (Rust/Go) untuk memitigasi risiko *spatial memory safety* secara total.
