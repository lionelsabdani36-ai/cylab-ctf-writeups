# Writeup: Cache Me Outside (Challenge ID: 146)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Heap Tcache Poisoning & Arbitrary Offset Byte Write (CWE-129 / CWE-787)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 70
- **Author:** madStacks
- **Flag:** `academy{5c9838eff837a883a30c38001280f07d}`

---

## Problem Statement & Scope
Tantangan `Cache Me Outside` menyajikan program biner Linux x86_64 (`heapedit`) yang dikompilasi menggunakan glibc 2.27 tanpa proteksi PIE (*Position Independent Executable*). Program ini dirancang untuk menguji pemahaman peserta terkait struktur internal pengalokasi memori heap Linux, khususnya subsistem *Thread Local Caching* (tcache) yang diperkenalkan pada glibc 2.26+.

Program membaca isi `flag.txt` ke dalam buffer, mengalokasikan 7 chunk berturut-turut berisi string bendera (`"Congrats! Your flag is: " + flag`), mengalokasikan 1 chunk tipuan (*dummy chunk*) berisi string pengalih (`"Sorry! This won't help you..."`), kemudian membebaskan (*free*) chunk bendera ke-7 dan chunk tipuan ke antrean tcache. Program memberikan satu kali kesempatan kepada pengguna untuk menuliskan 1 byte nilai arbitrer pada offset memori relatif terhadap alamat alokasi awal. Terakhir, program mengalokasikan buffer baru dan mencetak isinya ke stdout.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Arsitektur Tcache pada glibc 2.27:**
   Mulai glibc 2.26, pengalokasi memori heap menambahkan mekanisme *Thread Local Caching* (tcache) untuk mempercepat alokasi berukuran kecil (hingga 1032 byte pada arsitektur 64-bit) tanpa memerlukan kunci mutex per arena. Setiap thread memiliki struktur metadata `tcache_perthread_struct` yang dialokasikan di pangkal heap (`heap_base + 0x10`):
   ```c
   typedef struct tcache_perthread_struct {
       uint16_t counts[TCACHE_MAX_BINS];       // 64 bins (128 byte)
       tcache_entry *entries[TCACHE_MAX_BINS]; // 64 pointer antrean (512 byte)
   } tcache_perthread_struct;
   ```
   Setiap bin tcache mengelola daftar berantai tunggal (*singly-linked list*) berorientasi LIFO (*Last In, First Out*). Ketika alokasi berukuran tertentu dibebaskan (`free`), chunk tersebut dimasukkan ke kepala daftar (`entries[bin_idx]`). Saat `malloc` meminta memori berukuran sama, glibc langsung mengambil chunk teratas dari `entries[bin_idx]` tanpa memeriksa integritas pointer secara ketat (glibc 2.27 belum mengimplementasikan *Safe Linking*).

2. **Tata Letak Chunk dan Status Antrean Tcache:**
   - Ukuran payload yang dialokasikan adalah 128 byte (0x80). Dengan metadata chunk header 16 byte (prev_size + size), ukuran total chunk adalah 0x90 byte.
   - Chunk ukuran 0x90 dipetakan ke bin index 7 pada tcache:
     - `p_buf_first` berada di alamat `0x6034a0`.
     - Chunk bendera ke-7 berada di alamat `0x603800`.
     - Chunk tipuan (`p_buf_last`) berada di alamat `0x603890`.
   - Setelah `free(p_buf)` dan `free(p_buf_last)` dipanggil, status antrean bin 7 pada `tcache->entries[7]` adalah:
     ```text
     entries[7] -> 0x603890 (dummy) -> 0x603800 (flag buffer)
     ```

3. **Kerentanan Penulisan Byte Relatif Tanpa Batas (Out-of-Bounds Byte Overwrite, CWE-129 / CWE-787):**
   Program meminta input berupa integer bertanda (*signed long*) dan sebuah karakter:
   ```c
   long offset;
   char val;
   scanf("%ld", &offset);
   scanf(" %c", &val);
   *(p_buf_first + offset) = val;
   ```
   Program sama sekali tidak memvalidasi batas nilai `offset`. Karena `offset` bertipe signed integer, pengguna dapat memberikan nilai negatif untuk memanipulasi alamat memori di belakang `p_buf_first`, termasuk struktur metadata `tcache_perthread_struct` yang terletak di `0x602088`.

4. **Keracunan Tcache (Tcache Poisoning via Single-Byte Overwrite):**
   Alamat entri bin 7 tcache di memori biner adalah `0x602088`.
   Jarak relatif dari `p_buf_first` (`0x6034a0`) ke `0x602088` dihitung secara matematis:
   ```text
   Offset = 0x602088 - 0x6034a0 = -5144
   ```
   Nilai yang tersimpan pada `0x602088` saat ini adalah pointer 64-bit `0x0000000000603890` (menunjuk ke buffer tipuan).
   Dengan menuliskan nilai `0x00` pada offset `-5144`, byte terendah (*least significant byte*) pointer tersebut berubah dari `0x90` menjadi `0x00`. Akibatnya, pointer kepala tcache berubah menjadi `0x0000000000603800` (menunjuk langsung ke chunk ke-7 yang memuat teks bendera).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Struktur Memori Biner dengan GDB/GEF:**
   Jalankan biner di bawah debugger dan pasang breakpoint pada pemanggilan `free` dan `malloc` terakhir:
   - Identifikasi alamat `p_buf_first`: `0x6034a0`.
   - Identifikasi alamat `tcache_perthread_struct`: `0x602010`.
   - Hitung offset array pointer `entries[7]`: `0x602050 + (7 * 8) = 0x602088`.
2. **Kalkulasi Offset Negatif:**
   Hitung perbedaan alamat dalam desimal:
   ```text
   0x602088 - 0x6034a0 = -5144
   ```
3. **Penyusunan Masukan Overwrite:**
   - Masukan alamat: `-5144\n`
   - Masukan nilai: `\x00` (karakter null / byte 0)
4. **Eksekusi Pengalokasian Akhir:**
   Setelah overwrite dilakukan:
   - Program mengeksekusi `buffer_to_print = malloc(128);`
   - Pengelola memori glibc melayani permintaan dari `tcache->entries[7]` yang kini menunjuk ke `0x603800`.
   - Program memanggil `puts(buffer_to_print + 16);`.
   - Teks bendera tercetak ke layar:
     ```text
     Address: Value: lag is: picoCTF{5c9838eff837a883a30c38001280f07d}
     ```
5. **Hasil Pembacaan Flag:**
   - Native Flag: `picoCTF{5c9838eff837a883a30c38001280f07d}`
   - Token Platform CyLab: `academy{5c9838eff837a883a30c38001280f07d}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{5c9838eff837a883a30c38001280f07d}`
- **Native PicoCTF Flag:** `picoCTF{5c9838eff837a883a30c38001280f07d}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_146_cache_me_outside.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Validasi Batas Indeks dan Offset Penunjuk Memori (Strict Bounds Checking):**
   Setiap operasi pengalamatan memori berbasis masukan pengguna wajib memverifikasi batas minimum dan maksimum (*array boundary check*):
   ```c
   if (offset < 0 || offset >= BUFFER_MAX_LEN) {
       fprintf(stderr, "Indeks offset di luar batas memori yang diizinkan!\n");
       exit(EXIT_FAILURE);
   }
   ```
2. **Pengadopsian Safe Linking pada Pengalokasi Heap Modern:**
   Glibc versi 2.32+ telah mengimplementasikan mitigasi *Safe Linking* pada tcache dan fastbins. Pointer `next` diacak (*mangled*) menggunakan operasi XOR dengan alamat pointer yang digeser secara acak:
   ```c
   PROTECT_PTR(pos, ptr) = ((uintptr_t)(pos) >> 12) ^ (uintptr_t)(ptr)
   ```
   Hal ini mencegah manipulasi pointer heap satu byte (*partial overwrite*) tanpa kebocoran basis alamat memori ASLR (*heap leak*).
3. **Pembersihan Data Sensitif Pasca Penggunaan (Zeroization):**
   Data sensitif seperti kunci kriptografis atau token bendera wajib dibersihkan dari memori segera setelah tidak lagi dibutuhkan menggunakan fungsi `explicit_bzero()` atau `memset_s()` guna mencegah sisa data terbaca kembali melalui alokasi heap berikutnya.
