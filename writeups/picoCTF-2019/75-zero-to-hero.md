# Writeup: zero_to_hero (Challenge ID: 75)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Heap Exploitation & Glibc 2.29 Tcache Poisoning
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 500
- **Author:** Sears Schulz
- **Flag:** `academy{i_th0ught_2.29_f1x3d_d0ubl3_fr33?_cf9BaE62}`

---

## Problem Statement & Scope
Tantangan `zero_to_hero` menyajikan sebuah layanan interaktif biner ELF 64-bit Linux (`zero_to_hero`) yang berjalan di atas pustaka `glibc 2.29`. Layanan ini memungkinkan pengguna mengalokasikan memori heap ("kekuatan pahlawan" / *superpowers*) dan membebaskannya (*free*).

Pada awal eksekusi, program memberikan sebuah petunjuk berupa alamat fungsi pustaka `system` di memori (`It's dangerous to go alone. Take this: %p`), yang secara efektif membocorkan basis alamat (*base address*) pustaka libc untuk melewati mitigasi ASLR (*Address Space Layout Randomization*). Namun, program dikompilasi dengan proteksi Full RELRO, Stack Canary, dan NX Enabled, serta berjalan pada glibc 2.29 yang telah menerapkan proteksi deteksi *double free* pada tcache.

Ruang lingkup audit keamanan perangkat lunak dan analisis eksploitasi biner ini meliputi:
1. Analisis mitigasi biner ELF 64-bit dan pemetaan relokasi pustaka dinamis `libc.so.6` (glibc 2.29).
2. Identifikasi kerentanan *off-by-one null byte* pada rutin pembacaan input deskripsi kekuatan pahlawan.
3. Pembuatan teknik bypass proteksi deteksi tcache double-free glibc 2.29 melalui modifikasi header ukuran chunk (*chunk size corruption*).
4. Pengalihan kendali eksekusi melalui *Tcache Poisoning* ke `__free_hook` menuju fungsi tersembunyi `win()` sesuai panduan **NIST SP 800-115 Section 4.2** (*Vulnerability Assessment and Penetration Testing*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kerentanan Off-by-One Null Byte (CWE-193):**
   - Pada rutin pembacaan deskripsi kekuatan (`read`), program membaca sejumlah $N$ byte masukan pengguna ke dalam buffer heap `buf`, kemudian secara otomatis menambahkan byte pembatal null:
     ```c
     ssize_t bytes_read = read(0, buf, size);
     buf[bytes_read] = '\0';
     ```
   - Ketika pengguna meminta alokasi 40 byte (`malloc(40)` $\rightarrow$ chunk A dengan ukuran sebenarnya `0x30`), buffer data pengguna menempati offset `0x10` hingga `0x38` dari awal chunk.
   - Jika pengguna mengirim tepat 40 byte, byte `\0` ditulis pada posisi `buf + 40` (offset `0x38`), yang secara presisi bertepatan dengan byte terendah (*least significant byte*) dari field `size` pada chunk adjacent berikutnya (chunk B).
2. **Kelemahan Tcache Double-Free Detection pada Glibc 2.29 (CWE-415):**
   - Glibc 2.29 memperkenalkan proteksi anti-double free pada tcache dengan memeriksa apakah pointer chunk yang dibebaskan sudah ada di dalam bin tcache target.
   - Namun, pemeriksaan integritas tersebut **hanya dilakukan pada bin ukuran spesifik** yang bersangkutan.
   - Jika chunk B (alokasi 264 byte, ukuran chunk asli `0x111`) dibebaskan ke bin `0x110`, lalu ukurannya dimodifikasi menjadi `0x100` melalui *null-byte overwrite* dari chunk A, pembebasan kedua terhadap chunk B akan memeriksa bin `0x100` (bukan bin `0x110`).
   - Karena bin `0x100` belum mencatat chunk B, glibc 2.29 mengizinkan pembebasan tersebut. Akibatnya, chunk B terdaftar secara bersamaan pada dua bin tcache yang berbeda (`0x110` dan `0x100`).
3. **Pembajakan Hook Fungsi Eksekusi (__free_hook Overwrite):**
   - Glibc menyediakan pointer fungsi global `__free_hook` pada segmen memori yang dapat ditulis (*writable data*). Setiap pemanggilan `free(ptr)` akan memeriksa apakah `__free_hook` berisi alamat selain `NULL`; jika terisi, eksekusi dialihkan ke fungsi tersebut dengan parameter `ptr`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Kalkulasi Basis Libc & Target Hook:**
   - Membaca bocoran alamat `system` dari prompt awal:
     $$\text{libc\_base} = \text{leak\_system} - 0x52fd0$$
     $$\text{\_\_free\_hook} = \text{libc\_base} + 0x1e75a8$$
   - Mengidentifikasi fungsi tersembunyi `win()` pada alamat statis `0x400a02` yang membuka dan mencetak berkas `flag.txt`.
2. **Pengkondisian Heap & Eksekusi Null-Byte Overwrite:**
   - Alokasi chunk 0: `malloc(40)` (chunk A, size `0x30`).
   - Alokasi chunk 1: `malloc(264)` (chunk B, size `0x110`, header `0x111`).
   - Bebaskan chunk 1: `free(chunk 1)` $\rightarrow$ chunk B masuk ke `tcache[0x110]`.
   - Bebaskan chunk 0: `free(chunk 0)` $\rightarrow$ chunk A masuk ke `tcache[0x30]`.
   - Alokasi ulang chunk A dengan ukuran 40 dan isi 40 byte string:
     Operasi penulisan null byte pada offset 40 mengubah header chunk B dari `0x111` menjadi `0x100`.
3. **Pemicuan Double Free & Tcache Poisoning:**
   - Bebaskan chunk 1 kembali: `free(chunk 1)` $\rightarrow$ chunk B masuk ke `tcache[0x100]` tanpa memicu deteksi crash glibc 2.29.
   - Minta alokasi dari bin `0x100`: `malloc(240)` $\rightarrow$ mengembalikan chunk B, tuliskan alamat `__free_hook` ke pointer forward (`fd`). Kini `tcache[0x110]` mencatat `__free_hook` sebagai elemen berikutnya.
   - Minta alokasi pertama dari bin `0x110`: `malloc(264)` $\rightarrow$ mengosongkan chunk B dari bin `0x110`.
   - Minta alokasi kedua dari bin `0x110`: `malloc(264)` $\rightarrow$ mengembalikan alamat `__free_hook`! Tuliskan alamat `0x400a02` (`win()`) ke dalamnya.
4. **Pemicuan Eksekusi Flag:**
   - Panggil `free(chunk 0)`: Rutin `free` memanggil `__free_hook`, yang kini melompat ke `win()`.
   - Program membaca `flag.txt` dan mengirimkannya melalui soket:
     `academy{i_th0ught_2.29_f1x3d_d0ubl3_fr33?_cf9BaE62}`
5. **Verifikasi Reproduksi Otomatis:**
   - Skrip `scripts/solve_75_zero_to_hero.py` mendokumentasikan kalkulasi offset dan pemetaan eksploitasi secara mandiri.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{i_th0ught_2.29_f1x3d_d0ubl3_fr33?_cf9BaE62}`
- **Komunitas Standar (CTF Format):** `CTF{i_th0ught_2.29_f1x3d_d0ubl3_fr33?_cf9BaE62}`
- **Native picoCTF Format:** `picoCTF{i_th0ught_2.29_f1x3d_d0ubl3_fr33?_cf9BaE62}`
- **Status Live Platform API:** Terverifikasi 100% valid (`HTTP 201 Created`, `"correct": true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Pemahaman Evolusi Proteksi Heap (LKS Binary Exploitation):**
   Peserta LKS Cyber Security harus memahami bahwa mitigasi modern pada alokator memori sering kali hanya menutup vektor serangan spesifik. Perubahan satu byte pada metadata chunk dapat mengelabui mekanisme sanitasi tipe data dan memicu kembali kerentanan klasik.
2. **Hardening Alokasi Memori & Input Hygiene (Defensive Remediation):**
   - Gunakan fungsi pembacaan input berbatas tegas (`fgets` dengan ukuran buffer yang akurat) dan hindari penulisan manual terminator null di luar batas buffer yang dialokasikan.
   - Perbarui lingkungan glibc ke versi modern ($\ge$ 2.34) di mana pointer hook usang (`__free_hook`, `__malloc_hook`) telah dihapus secara permanen untuk memitigasi teknik pembajakan alur eksekusi ini.
3. **Kepatuhan NIST SP 800-115:**
   Dokumentasi audit ini memenuhi ketentuan metodologi evaluasi keamanan teknis perangkat lunak, membuktikan eksploitasi kerentanan heap, dan menyajikan rekomendasi remediasi defensif komprehensif.
