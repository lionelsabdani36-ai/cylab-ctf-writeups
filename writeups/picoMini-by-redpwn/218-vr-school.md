# Writeup: vr-school (Challenge ID: 218)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Heap Use-After-Free & Type Confusion to Syscall ROP (CWE-416 / CWE-843)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 500
- **Author:** redpwn
- **Flag:** `picoCTF{0nl1ne_d3bat3_sux}`

---

## Problem Statement & Scope
Tantangan `vr-school` menyajikan aplikasi pengelolaan data biner siswa interaktif berbasis memori tumpukan (*heap*) pada sistem operasi Linux x86_64 dengan pustaka GNU C Library (`glibc`). Layanan menyediakan menu interaktif berulang:
1. `0. Create a student` : Mengalokasikan struktur data siswa baru.
2. `1. Set student name` : Mengalokasikan dan menetapkan buffer nama siswa.
3. `2. Print student name` : Menampilkan data nama siswa melalui dereferensi pointer.
4. `3. Study` : Mengeksekusi pointer fungsi studi siswa.
5. `4. Free student` : Menghapus objek siswa dari memori.

Tantangan menguji kompetensi peserta dalam menganalisis manajemen memori tingkat rendah (*heap allocator internals*), memanfaatkan pointer menggantung (*dangling pointer* / Use-After-Free), menyusun kebingungan tipe data (*type confusion*) akibat alokasi ulang ukuran seragam (*same-size chunk recycling*), mengekstrak kebocoran alamat acak ASLR (*information disclosure*), serta membangun rantai eksekusi *Return-Oriented Programming* (ROP) berbasis panggilan sistem langsung (*direct syscalls*) untuk mengeksfiltrasi berkas rahasia `flag.txt`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kegagalan Pembersihan Pointer Setelah Pembebasan Memori (Use-After-Free, CWE-416):**
   Struktur data objek siswa didefinisikan dengan ukuran 24 byte (0x18):
   ```c
   struct student {
       void (*study_fn)(struct student *);
       char *name;
       size_t name_len;
   };
   ```
   Saat pengguna memilih menu penghapusan objek siswa (opsi 4), program memanggil `free(student->name)` dan `free(student)`. Namun, alamat pointer siswa pada array global pelacak tidak diatur ke `NULL` (`dangling pointer`). Hal ini memungkinkan objek yang telah dibebaskan untuk terus diakses melalui menu *Print student name* atau dimanipulasi melalui siklus alokasi berikutnya.
2. **Kebingungan Tipe Data Melalui Daur Ulang Chunk Heap (Type Confusion, CWE-843):**
   Dalam manajemen *glibc heap*, alokasi memori dengan kelas ukuran identik (0x18 yang dibulatkan ke ukuran chunk 0x20) akan menggunakan kembali chunk yang baru saja dilepaskan. Jika penyerang mengalokasikan buffer nama siswa (`name buffer`) berukuran 24 byte segera setelah membebaskan objek siswa, pengalokasi heap akan mengembalikan alamat memori dari objek siswa yang dibebaskan tersebut. Data masukan teks nama yang dikirim penyerang menimpa langsung bidang-bidang terstruktur `{study_fn, name_ptr, name_len}`, memberikan kendali penuh terhadap pointer dereferensi internal.
3. **Penyusunan Primitif Arbitrary Read & Stack Leak via `__environ`:**
   Dengan mengontrol `name_ptr` pada objek palsu, pemanggilan opsi 2 (*Print student name*) menghasilkan primitif pembacaan memori sembarang (*arbitrary read*):
   - Menunjuk ke `malloc@GOT` atau `puts@GOT` membocorkan alamat fungsi pustaka libc, mematahkan proteksi ASLR.
   - Menunjuk ke simbol `__environ` di libc membocorkan alamat penunjuk tumpukan aktif (*live stack pointer*), memungkinkan perhitungan offset frame pengembalian fungsi (*saved RIP*).
4. **Eksfiltrasi Terarah via Open-Read-Write (ORW) ROP Chain:**
   Karena versi glibc target telah menonaktifkan kait alokator (`__free_hook` dan `__malloc_hook`), serta tidak tersedianya jalur eksekusi `system("/bin/sh")` langsung, penyerang menerapkan teknik keracunan fastbin (*fastbin poisoning*) untuk mengalokasikan chunk palsu tepat di atas frame tumpukan *saved RIP*. Payload ROP menyusun pemanggilan sistem:
   `sys_open("flag.txt", 0)` -> `sys_read(fd=3, bss, 0x100)` -> `sys_write(fd=1, bss, 0x100)`, yang mengalirkan byte flag ke konsol saat fungsi kembali.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Mitigasi Biner & Arsitektur:**
   Pemeriksaan parameter keamanan biner:
   - Arch: `x86-64 little-endian` (`ELF 64-bit LSB shared object`)
   - RELRO: `Partial RELRO`
   - Stack Canary: `No canary found`
   - NX: `NX enabled` (tumpukan memori tidak dapat dieksekusi langsung)
   - PIE: `PIE enabled` (basis alamat segmen kode teracak)
2. **Pemicuan UAF & Rekayasa Objek Siswa Palsu:**
   - Alokasi dua siswa: Siswa 0 dan Siswa 1.
   - Bebaskan Siswa 0 (meninggalkan pointer menggantung pada slot 0).
   - Alokasikan buffer nama berukuran 0x18 untuk Siswa 1. Pengalokasi heap mendaur ulang chunk Siswa 0.
   - Kirim 24 byte payload yang memalsukan `name_ptr` agar menunjuk ke entri Global Offset Table (`puts@GOT`).
3. **Ekstraksi Kebocoran Alamat Libc dan Tumpukan (Stack Pointer):**
   - Panggil menu `2. Print student name` untuk Siswa 0: program mencetak 8 byte alamat `puts` dari libc.
   - Hitung basis libc: `libc_base = leaked_puts - puts_offset`.
   - Perbarui `name_ptr` agar menunjuk ke simbol libc `__environ`:
     `target_environ = libc_base + offset_environ`.
   - Panggil menu `2` kembali: program mencetak alamat tumpukan proses aktif.
   - Hitung alamat frame kembali: `saved_rip = leaked_stack - stack_delta`.
4. **Fastbin Poisoning & Penanaman ROP Chain:**
   - Penuhi bin tcache 0x18 dengan 7 pembebasan chunk guna memaksa alokator beralih ke linked-list fastbin klasik.
   - Bebaskan Siswa 0 ke dalam fastbin dan timpa pointer maju (`fd`) dengan alamat `saved_rip`.
   - Alokasikan ulang dua chunk: alokasi kedua mengembalikan memori yang tumpang tindih dengan saved RIP pada stack.
   - Tuliskan rantai ROP Open-Read-Write (ORW):
     - `pop rdi; ret` -> pointer string `"flag.txt"`
     - `pop rsi; ret` -> `0` (`O_RDONLY`)
     - `pop rax; ret` -> `2` (`sys_open`)
     - `syscall; ret`
     - `pop rdi; ret` -> `3` (`fd`)
     - `pop rsi; ret` -> alamat `.bss`
     - `pop rdx; ret` -> `0x100`
     - `pop rax; ret` -> `0` (`sys_read`)
     - `syscall; ret`
     - `pop rdi; ret` -> `1` (`stdout`)
     - `pop rax; ret` -> `1` (`sys_write`)
     - `syscall; ret`
5. **Batas Validasi Validator & Normalisasi Token:**
   Pengujian empiris langsung pada REST API CyLab menunjukkan bahwa validator tantangan ini (event `picoMini by redpwn`) menerima format wrapper asli `picoCTF{0nl1ne_d3bat3_sux}` dengan status HTTP 201 Created (`correct: true`). Sebaliknya, pengiriman dengan wrapper CyLab `academy{0nl1ne_d3bat3_sux}` ditolak dengan `{"correct": false}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `picoCTF{0nl1ne_d3bat3_sux}`
- **Wrapper Validator:** Native event wrapper (`picoCTF{...}`)
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_218_vr_school.py`.

### Re-verifikasi Audit Batch 185 (2026-11-09 UTC, sesi REST siswa `Arielwin` / user id 1072359)

| Token diuji | Wrapper | HTTP | Respons API |
| :--- | :--- | :--- | :--- |
| `picoCTF{0nl1ne_d3bat3_sux}` | native event | 201 | `{"user":1072359,"challenge":218,"flag":"picoCTF{0nl1ne_d3bat3_sux}","correct":true,"historical":false}` |
| `academy{0nl1ne_d3bat3_sux}` | CyLab rekey | 201 | `{"user":1072359,"challenge":218,"flag":"academy{0nl1ne_d3bat3_sux}","correct":false,"historical":false}` |

- **Temuan format validator:** Modul backport event `picoMini by redpwn` tidak direkey ke prefix `academy{...}`.
- **Reproduktifitas offline:** Solver `scripts/solve_218_vr_school.py` merekonstruksi eksploitasi UAF/fastbin ROP dan mengekstrak token native terverifikasi.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Defensive Pointer Hygiene (Nullification on Free):**
   Setiap kali memori heap dilepaskan melalui `free()`, pointer referensi harus segera diatur ke `NULL` (`pointer = NULL;`) untuk mematikan risiko eksploitasi pointer menggantung (*dangling pointer / UAF*):
   ```c
   void free_student(int idx) {
       if (students[idx] != NULL) {
           free(students[idx]->name);
           free(students[idx]);
           students[idx] = NULL;
       }
   }
   ```
2. **Kompilasi dengan Proteksi Penuh (Full RELRO & Canaries):**
   - Mengaktifkan `Full RELRO` (`-Wl,-z,relro,-z,now`) agar tabel GOT bersifat read-only setelah inisialisasi linker dinamis, mencegah pembacaan dan pembajakan fungsi melalui GOT overwrite.
   - Mengaktifkan `-fstack-protector-strong` guna menggagalkan upaya pembajakan frame kembali stack melalui teknik stack pivoting atau tcache poisoning ke tumpukan.
3. **Pemberlakuan Safe Allocator & Pointer Mangling:**
   Pembaruan glibc modern memberlakukan *safe-linking pointer mangling* pada struktur tcache/fastbin (`P' = (L >> 12) ^ P`), mempersulit penyerang memanipulasi pointer `fd` tanpa membocorkan basis heap secara tepat.