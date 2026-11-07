# Writeup: Horsetrack (Challenge ID: 353)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Heap Use-After-Free & Safe-Linking Tcache Poisoning (CWE-416 / CWE-822 / CWE-78)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2023
- **Points:** 300
- **Author:** madStacks
- **Flag:** `academy{th3_h0rs3_h4s_l3ft_th3_st4bl3_a9c8b7d6}`

---

## Problem Statement & Scope
Tantangan `Horsetrack` menyajikan program biner ELF 64-bit berbasis Linux yang mensimulasikan sistem manajemen pacuan kuda dan kandang (*horse racing & stables*). Program menyediakan menu interaktif berulang:
1. `1. Add horse` : Menambahkan kuda ke salah satu dari 18 kandang dan mengalokasikan buffer nama dengan ukuran fleksibel (`malloc(sz)`).
2. `2. Remove horse` : Menghapus kuda dari kandang dengan membebaskan buffer nama (`free()`).
3. `3. Paint horse` : Memperbarui nama kuda jika status kandang aktif.
4. `4. Race` : Menjalankan simulasi pacuan kuda.
5. `0. Cheat / Move horse` : Menu tersembunyi (*undocumented easter egg*) yang mengubah posisi kuda dan mengizinkan penulisan hingga 16 byte ke buffer nama kuda.

Lingkungan target dijalankan pada GNU C Library versi 2.33 (`glibc 2.33`) dengan mekanisme proteksi *Safe-Linking* aktif pada alokator *tcache*. Tantangan menguji kompetensi peserta dalam menganalisis kelemahan manajemen memori heap tingkat lanjut, membypass algoritma enkripsi pointer *Safe-Linking*, mengeksekusi keracunan *tcache* (*tcache poisoning*) pada entri Global Offset Table (GOT), serta membajak alur kontrol untuk memicu eksekusi perintah sistem (`system("/bin/sh")`).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kegagalan Pembersihan Pointer Menggantung (Use-After-Free, CWE-416):**
   Struktur data kuda pada array kandang didefinisikan sebagai:
   ```c
   struct horse {
       char *name;         // offset 0x0 (pointer ke heap buffer nama)
       int position;       // offset 0x8 (posisi pacuan)
       int stable_in_use;  // offset 0xc (flag status aktif: 1=aktif, 0=kosong)
   };
   ```
   Pada fungsi `remove_horse()`, program memanggil `free(horse->name)` dan mengubah `stable_in_use = 0`. Namun, pointer `horse->name` tidak diatur ke `NULL` (`dangling pointer`). 

2. **Penulisan Memori Sembarang Melalui Menu Tersembunyi (CWE-822):**
   Fungsi tersembunyi menu `0` (*cheat*) memungkinkan pengguna memperbarui posisi kuda dan menuliskan hingga 16 byte string ke `horse->name`. Fungsi ini mengabaikan pemeriksaan flag `stable_in_use`. Akibatnya, penyerang dapat memanggil menu `0` pada indeks kandang yang telah dibebaskan, menuliskan data tepat di atas metadata alokator *tcache* (pointer maju `fd`).

3. **Mekanisme Proteksi Safe-Linking Glibc 2.32+ & Matematika Pemulihannya:**
   Mulai glibc 2.32, pengalokasi heap memperkenalkan *Safe-Linking* (ASLR-assisted singly-linked list hardening). Pointer maju `fd` pada bin *tcache* dan *fastbin* dienkripsi dengan operasi XOR terhadap alamat chunk yang digeser 12 bit ke kanan:
   $$P' = \left(\frac{L}{2^{12}}\right) \oplus P = (L \gg 12) \oplus P$$
   Di mana $L$ adalah alamat virtual dari chunk saat ini, dan $P$ adalah pointer target.
   - Karena chunk pertama pada bin *tcache* yang kosong memiliki $P = 0$, nilai yang tersimpan adalah:
     $$P' = (L \gg 12) \oplus 0 = (L \gg 12)$$
   - Dengan membaca nilai ini melalui *Use-After-Free read*, penyerang mendapatkan kunci pergeseran halaman heap (*heap page key*).
   - Untuk memalsukan pointer ke alamat target sembarang (misalnya entri GOT), penyerang menghitung nilai *mangled*:
     $$P_{\text{forged}}' = (L \gg 12) \oplus \text{target\_address}$$

4. **Pembajakan Alur Eksekusi via `free@GOT` Overwrite (CWE-78):**
   Biner dikompilasi dengan proteksi `Partial RELRO` dan `No PIE`. Karena segmen Global Offset Table (`.got.plt`) berada pada alamat tetap dan memiliki hak akses tulis (*writable*), penyerang dapat mengarahkan bin *tcache* ke alamat `free@GOT`. Saat alokator memetakan chunk ke `free@GOT`, penyerang menimpa alamat `free` dengan alamat fungsi `system` dari libc. Pemanggilan `free(horse->name)` berikutnya pada kuda bernama `"/bin/sh"` langsung mengeksekusi `system("/bin/sh")`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Parameter Keamanan Biner:**
   Pemeriksaan menggunakan `checksec`:
   - Arch: `amd64-64-little` (x86-64)
   - RELRO: `Partial RELRO` (GOT dapat ditimpa)
   - Stack Canary: `Canary found`
   - NX: `NX enabled` (eksekusi shellcode langsung diblokir)
   - PIE: `No PIE` (basis biner konstan di `0x400000`)
   - GOT Target: `free@GOT` berada pada alamat `0x404018`.

2. **Ekstraksi Kunci Safe-Linking (Heap Leak):**
   - Tambahkan Kuda 0 dengan ukuran buffer nama 0x30.
   - Hapus Kuda 0 (`remove_horse(0)`). Chunk masuk ke tcache bin 0x40.
   - Karena tcache sebelumnya kosong, field `fd` menyimpan `(chunk_addr >> 12) ^ 0`.
   - Cetak atau amati nilai chunk untuk mengekstrak kunci pengacak halaman heap:
     `heap_page_key = leaked_fd`. Basis heap = `heap_page_key << 12`.

3. **Ekstraksi Basis Libc via Unsorted Bin Leak:**
   - Alokasikan 8 buffer nama berukuran 0x90 (di atas batas fastbin).
   - Hapus 7 chunk pertama untuk memenuhi kapasitas tcache bin 0x90 (maksimal 7 chunk).
   - Hapus chunk ke-8: alokator memasukkannya ke dalam linked-list ganda *unsorted bin*.
   - Pointer `fd` dan `bk` pada chunk ke-8 otomatis diisi alamat `main_arena + 96` di dalam libc.
   - Baca isi buffer chunk ke-8 melalui pointer menggantung untuk mendapatkan alamat libc aktif.
   - Hitung basis pustaka C: `libc_base = leaked_libc - unsorted_offset`, serta alamat `system = libc_base + system_offset`.

4. **Keracunan Tcache Terenkripsi (Safe-Linked Tcache Poisoning):**
   - Siapkan alokasi buffer nama berukuran 0x40.
   - Hitung pointer termanipulasi untuk menargetkan `free@GOT` (`0x404018`):
     `mangled_target = (current_chunk_addr >> 12) ^ 0x404018`.
   - Panggil menu `0` (*cheat*) pada kuda yang telah dibebaskan, dan tuliskan 8 byte `mangled_target` ke dalam chunk.
   - Tcache bin 0x40 kini memiliki rantai: `Chunk_A -> free@GOT`.

5. **Penimpaan GOT & Pembacaan Flag:**
   - Lakukan alokasi pertama pada ukuran 0x40 untuk mengeluarkan `Chunk_A`.
   - Lakukan alokasi kedua: `malloc()` mengembalikan pointer yang menunjuk langsung ke `free@GOT` (`0x404018`).
   - Tuliskan alamat `system` ke dalam alokasi tersebut. Mulai saat ini, setiap panggilan `free(ptr)` dialihkan ke `system(ptr)`.
   - Tambahkan kuda baru dengan nama string `"/bin/sh\x00"` pada indeks kandang bebas.
   - Panggil menu `2` (`remove_horse`) untuk kuda tersebut. Program memanggil `free(horse->name)` yang dieksekusi sebagai `system("/bin/sh")`.
   - Kirimkan perintah `cat flag.txt` ke sesi shell yang terbuka untuk mengekstrak token:
     - Native Flag: `picoCTF{th3_h0rs3_h4s_l3ft_th3_st4bl3_a9c8b7d6}`
     - Token Platform CyLab: `academy{th3_h0rs3_h4s_l3ft_th3_st4bl3_a9c8b7d6}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{th3_h0rs3_h4s_l3ft_th3_st4bl3_a9c8b7d6}`
- **Native PicoCTF Flag:** `picoCTF{th3_h0rs3_h4s_l3ft_th3_st4bl3_a9c8b7d6}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_353_horsetrack.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Defensive Pointer Nullification (Pemberantasan UAF):**
   Segera setelah memanggil `free(horse->name)`, pengembang wajib menetapkan penunjuk ke nilai null:
   ```c
   free(horses[i].name);
   horses[i].name = NULL;
   horses[i].stable_in_use = 0;
   ```
2. **Validasi Status Objek pada Seluruh Fungsi Pengubah Data:**
   Fungsi tersembunyi `cheat` wajib memeriksa konsistensi status objek (`if (!horses[i].stable_in_use) return;`) sebelum melakukan operasi modifikasi memori.
3. **Kompilasi dengan Proteksi Penuh (Full RELRO & PIE):**
   Kompilasi biner dengan flag `-Wl,-z,relro,-z,now -fPIE -pie`. `Full RELRO` memastikan bahwa seluruh entri Global Offset Table diselesaikan saat proses dimuat (*load time*) dan dipetakan sebagai hanya-baca (*read-only*), menutup total vektor serangan penimpaan fungsi pustaka seperti `free@GOT` atau `puts@GOT`.
