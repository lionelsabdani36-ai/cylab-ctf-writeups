# Writeup: sice_cream (Challenge ID: 55)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Glibc 2.23 Fastbin Dup & House of Orange FSOP
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 500
- **Author:** Samuel
- **Flag:** `academy{th3_r3al_questi0n_is_why_1s_libc_2.23_still_4_th1ng_8d25b643}`

---

## Problem Statement & Scope
Tantangan `sice_cream` menyajikan layanan biner ELF 64-bit Linux yang beroperasi pada pustaka `glibc 2.23`. Program ini mengimplementasikan toko virtual yang menyediakan fitur membeli sice cream (`malloc` ukuran fastbin $\le 0x58$), memakan sice cream (`free` pointer yang dipilih), serta memperkenalkan diri kembali (`reintroduce`, menulis hingga 256 byte ke variabel global `name` pada segmen `.bss`).

Pemeriksaan keamanan biner (`checksec`):
- **Arch:** amd64-64-little (64-bit ELF)
- **RELRO:** Full RELRO (Global Offset Table bersifat read-only)
- **Stack Canary:** Canary found
- **NX:** NX enabled (Eksekusi kode pada stack/heap dicegah)
- **PIE:** No PIE (Alamat kode dan variabel `.bss` berada pada offset statis 0x400000 dan 0x602000)

Ruang lingkup audit keamanan perangkat lunak dan eksploitasi heap ini meliputi:
1. Analisis arsitektur manajemen memori heap pada pustaka glibc versi 2.23 (tanpa isolasi tcache).
2. Identifikasi kerentanan Use-After-Free / Double Free pada array pointer global.
3. Pembuatan chunk palsu (*fake chunk forging*) pada segmen data `.bss` dan pemalsuan linked list fastbin.
4. Eksfiltrasi basis alamat pustaka dinamis `libc.so.6` melalui pembebasan unsorted bin chunk ke `main_arena`.
5. Pengalihan alur kontrol eksekusi melalui File Stream Oriented Programming (FSOP / House of Orange) atau overwrite hook sesuai standar **NIST SP 800-115 Section 4.2**.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Dangling Pointer & Fastbin Double Free (CWE-416 & CWE-415):**
   - Fungsi `eat()` melakukan pemanggilan `free(creams[idx])` tetapi tidak mengosongkan pointer tersebut ke `NULL`:
     ```c
     free(*(void **)(&DAT_00602140 + idx * 8));
     // creams[idx] tidak diatur ke NULL!
     ```
   - Pada glibc 2.23, pemeriksaan integritas fastbin hanya memverifikasi bahwa chunk yang dibebaskan tidak identik dengan elemen teratas (*fasttop*).
   - Dengan membebaskan dua chunk secara bergantian (`free(A); free(B); free(A)`), penyerang menciptakan siklus sirkular pada singly linked list fastbin tanpa memicu abort.
2. **Kedekatan Memori BSS dan Pemalsuan Header Chunk (CWE-122):**
   - Buffer masukan `name` terletak di `0x602040`, persis di atas tabel pointer `creams` di `0x602140`.
   - Melalui fungsi `reintroduce()`, penyerang memiliki kendali penuh atas 256 byte pada `name`. Dengan menyusun byte header chunk palsu pada `0x602130` (misalnya ukuran fastbin `0x41`), penyerang dapat mengarahkan pointer `fd` chunk A ke alamat tersebut. Alokasi berikutnya akan mengembalikan memori yang mencakup entri `creams[0]`.
3. **Eksfiltrasi Libc melalui Unsorted Bin:**
   - Ketika chunk berukuran lebih besar dari batasan fastbin ($> 0x80$, misalnya ukuran palsu `0x91` atau `0xc1`) dibebaskan, chunk tersebut masuk ke unsorted bin.
   - Rutin pengalokasian glibc secara otomatis menuliskan pointer circular doubly linked list unsorted bin ke `fd` dan `bk`, yang menunjuk langsung ke `main_arena + 88` di dalam libc. Membaca string `name` membocorkan alamat ini ke penyerang.
4. **Pembajakan Eksekusi melalui FSOP / Hook Overwrite:**
   - Dengan basis libc yang telah diketahui, penyerang dapat memodifikasi struktur file stream (`_IO_list_all`) agar menunjuk ke fake `_IO_FILE` (metode House of Orange). Saat program memanggil `abort()` atau `exit()`, fungsi `_IO_flush_all_lockp` mengiterasi linked list file stream dan memicu pointer vtable palsu yang telah diarahkan ke `system("/bin/sh")`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inisialisasi BSS dan Double Free:**
   - Memasukkan nama awal untuk menginisialisasi buffer `name`.
   - Mengalokasikan dua chunk ukuran fastbin: chunk 0 (`0x50`) dan chunk 1 (`0x50`).
   - Memicu double free: `eat(0)` $\rightarrow$ `eat(1)` $\rightarrow$ `eat(0)`. Fastbin kini memiliki struktur: `chunk 0 -> chunk 1 -> chunk 0`.
2. **Penyusunan Fake Chunk dan Penguasaan Creams:**
   - Memanggil `reintroduce()` untuk menanam fake chunk header berukuran `0x41` pada `0x602130` tepat di atas `creams`.
   - Mengalokasikan chunk pertama: `buy(0x38)` dengan data `p64(0x602130)` untuk meracuni pointer `fd`.
   - Mengalokasikan chunk kedua dan ketiga untuk mengosongkan antrean fastbin. Chunk keempat yang dialokasikan mengembalikan pointer ke `0x602140` (`creams[0]`).
3. **Eksfiltrasi Libc via Unsorted Bin Free:**
   - Mengisi `creams[0]` dengan alamat fake unsorted bin chunk di `0x602040` (ukuran `0xc1` dengan bit `prev_inuse` disetel valid).
   - Memanggil `eat(0)` untuk membebaskan fake chunk tersebut ke unsorted bin. Glibc menulis alamat `main_arena + 88` ke field `fd` dan `bk`.
   - Memanggil `reintroduce()` dengan padding 16 byte non-null untuk mencetak alamat `main_arena` dan menghitung basis libc:
     $$\text{libc\_base} = \text{leak\_main\_arena} - 0x3c4b78$$
4. **Pemicuan Shell via FSOP / System:**
   - Menyusun struktur `_IO_FILE` sintesis di dalam buffer nama dengan parameter `_mode = 0`, `_IO_write_base = 2`, `_IO_write_ptr = 3`, dan vtable jump pointer mengarah ke `system()`.
   - Memicu pemrosesan unsorted bin chunk yang tidak valid untuk memaksa rutin penanganan kesalahan memanggil `_IO_flush_all_lockp`, mengeksekusi `system("/bin/sh")`, dan membaca berkas flag.
5. **Verifikasi Skrip Solver:**
   - Menjalankan `scripts/solve_55_sice_cream.py` untuk memvalidasi model eksploitasi secara mandiri.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{th3_r3al_questi0n_is_why_1s_libc_2.23_still_4_th1ng_8d25b643}`
- **Flag Komunitas:** `CTF{th3_r3al_questi0n_is_why_1s_libc_2.23_still_4_th1ng_8d25b643}`
- **Bukti Validasi:** Solver memverifikasi rangkaian fastbin corruption, perhitungan arena libc, dan pemetaan FSOP secara presisi.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Pembersihan Pointer Pasca Pembebasan (NULL Pointer Hygiene):**
   - Setiap pemanggilan fungsi `free(ptr)` wajib segera diikuti dengan penetapan pointer ke nol: `ptr = NULL;`. Hal ini secara total meniadakan potensi kerentanan Use-After-Free dan Double Free.
2. **Pembaruan Pustaka C Modern:**
   - Versi glibc yang lebih baru (glibc 2.27+ hingga 2.35+) telah menyematkan mitigasi proteksi tcache count, pointer mangling (*pointer encryption* via safe-linking `P ^ (L >> 12)`), dan validasi integritas vtable `_IO_vtable_check` yang secara otomatis menggagalkan eksploitasi tipe House of Orange.
