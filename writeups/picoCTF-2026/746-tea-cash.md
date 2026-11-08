# Writeup: tea-cash (Challenge ID: 746)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Heap Exploitation & Glibc Tcache Free-List Traversal (NIST SP 800-115 §4.4)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** picoCTF / CyLab Academy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{ef29b8f2d75bd216bf505de0d02fddef}`
- **Flag Komunitas:** `CTF{ef29b8f2d75bd216bf505de0d02fddef}`
- **Standar Referensi:** NIST SP 800-115 §4.4 (System and Application Vulnerability Testing), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer), glibc ptmalloc2 tcache LIFO mechanism.

---

## Problem Statement & Scope
Peserta dihadapkan pada layanan kasir memori interaktif berbasis biner ELF x86-64 `heapedit` yang berjalan pada port TCP ephemeral on-demand (`nc chatelaine.cylabacademy.net <port>`). 
Biner mengalokasikan 6 blok memori berukuran 0x80 byte (`malloc(0x80)`). Data rahasia kompetisi dibaca dari berkas lokal `flag.txt` dan disalin ke blok ke-6 pada offset 8 (`FLAG_OFFSET = sizeof(void*)`). 
Setelah seluruh blok dialokasikan dan data diinisialisasi, program membocorkan alamat blok pertama (`tcache head (start of free list) -> %p`) ke stdout, lalu membebaskan (*free*) keenam blok secara berurutan mundur dari indeks 5 ke 0:
```c
for (int i = CHUNK_COUNT - 1; i >= 0; --i) {
    free(chunks[i]);
}
```
Program kemudian meminta pengguna menginputkan 6 alamat memori secara berurutan sesuai rantai traversal free-list tcache. Setiap alamat yang dimasukkan diverifikasi kecocokannya dengan pointer `expected`, kemudian pointer berikutnya dibaca menggunakan `memcpy(&next, user_addr, sizeof(void*))`. Jika seluruh 6 alamat berhasil dimasukkan secara presisi, program mencetak string flag dari sisa memori blok ke-6.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Arsitektur Thread Local Caching (Tcache) Glibc
Sejak glibc 2.26, allocator memori default Linux (`ptmalloc2`) mengimplementasikan mekanisme *tcache* (Thread Local Caching) untuk mengoptimalkan kecepatan alokasi chunk berukuran kecil (hingga 1032 byte pada arsitektur 64-bit). Tcache mengelola bin terpisah untuk setiap thread tanpa memerlukan penguncian mutex arena global.
Struktur data free-list tcache berupa *singly-linked list* yang bekerja dengan disiplin LIFO (*Last-In, First-Out*):
- Ketika sebuah chunk dibebaskan (`free(p)`), pointer maju (*forward pointer* atau `fd`) disimpan pada 8 byte pertama dari area data pengguna (*user payload area*).
- Pointer `fd` tersebut menunjuk ke chunk yang dibebaskan sebelumnya pada tcache bin yang sama.
- Pointer global `tcache->entries[tc_idx]` (atau `head`) diperbarui menunjuk ke chunk yang baru saja dibebaskan.

### 2. Rekonstruksi Urutan Deallocation & Struktur Free-List
Pada `heapedit.c`, deallocation dieksekusi secara mundur:
```text
free(chunks[5]) -> tcache head = chunks[5], chunks[5]->fd = NULL
free(chunks[4]) -> tcache head = chunks[4], chunks[4]->fd = chunks[5]
free(chunks[3]) -> tcache head = chunks[3], chunks[3]->fd = chunks[4]
free(chunks[2]) -> tcache head = chunks[2], chunks[2]->fd = chunks[3]
free(chunks[1]) -> tcache head = chunks[1], chunks[1]->fd = chunks[2]
free(chunks[0]) -> tcache head = chunks[0], chunks[0]->fd = chunks[1]
```
Akibat disiplin LIFO, `chunks[0]` yang dibebaskan paling akhir menjadi `head` dari free-list tcache. Rantai pointer traversal yang terbentuk adalah:
$$\text{chunks}[0] \longrightarrow \text{chunks}[1] \longrightarrow \text{chunks}[2] \longrightarrow \text{chunks}[3] \longrightarrow \text{chunks}[4] \longrightarrow \text{chunks}[5] \longrightarrow \text{NULL}$$

### 3. Deterministik Heap Allocation Stride (0x90 Bytes)
Pada heap arena baru (heap bersih yang belum mengalami fragmentasi), alokasi `malloc(0x80)` menempatkan chunk secara berdampingan (*contiguous*).
Setiap chunk memiliki metadata header glibc sebesar 16 byte (0x10):
- 8 byte `prev_size` (offset 0x00 - 0x07)
- 8 byte `size` & chunk flags `A|M|P` (offset 0x08 - 0x0F)
- 128 byte user data area (offset 0x10 - 0x8F)
Total memori virtual per alokasi adalah $0x80 + 0x10 = 0x90$ byte.
Karena tidak ada intervensi alokasi lain di antara loop inisialisasi, jarak (*stride*) antar chunk pengguna bernilai konstan:
$$\text{chunks}[i] = \text{head} + i \times 0x90 \quad \text{untuk } i \in [0, 5]$$

### 4. Pelanggaran Prinsip Least Privilege & Information Exposure (CWE-200)
Mencetak alamat pointer heap `head` ke terminal pengguna mengekspos base address dari heap arena. Dikombinasikan dengan ketiadaan proteksi pointer (seperti *pointer mangling / safe-linking* pada glibc versi lama atau ketiadaan validasi integritas struktur tcache), penyerang dapat menghitung seluruh topologi memori tcache secara deterministik tanpa memerlukan kebocoran memori sekunder (*secondary memory leak*).

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Audit Statis Kode Sumber & Ekstraksi Logika Validasi
Audit statis terhadap berkas `heapedit.c` mengungkapkan bahwa program melakukan pengecekan alamat input menggunakan loop:
```c
void *expected = head;
for (int i = 0; i < CHUNK_COUNT; ++i) {
    void *user_addr = NULL;
    printf("Chunk %d address: ", i+1);
    scanf("%p", &user_addr);
    if (user_addr != expected) exit(1);
    void *next = NULL;
    memcpy(&next, user_addr, sizeof(void *));
    expected = next;
}
```
Untuk melewati validasi, penyerang harus mengirimkan alamat yang persis sama dengan nilai pointer `expected` pada setiap iterasi.

### Langkah 2: Formula Perhitungan Alamat Traversal
Dengan mengekstrak nilai awal `head` dari banner program, formula 6 langkah traversal dihitung sebagai berikut:
1. Iterasi 1: $\text{addr}_0 = \text{head}$
2. Iterasi 2: $\text{addr}_1 = \text{head} + 0x90$
3. Iterasi 3: $\text{addr}_2 = \text{head} + 0x120$
4. Iterasi 4: $\text{addr}_3 = \text{head} + 0x1b0$
5. Iterasi 5: $\text{addr}_4 = \text{head} + 0x240$
6. Iterasi 6: $\text{addr}_5 = \text{head} + 0x2d0$

### Langkah 3: Eksekusi Automasi Socket & Ekstraksi Flag
Menggunakan skrip Python `scripts/solve_746_tea_cash.py`:
1. Membuka koneksi socket TCP ke target `chatelaine.cylabacademy.net:<port>`.
2. Menangkap string `tcache head (start of free list) -> 0x...` dan mengonversi nilai heksadesimal ke integer `head`.
3. Mengirimkan string heksadesimal `hex(head + i * 0x90) + "\n"` sebanyak 6 kali dengan interval pacing 0.3 detik.
4. Menangkap pesan keberhasilan:
   `Correct traversal! Flag: academy{ef29b8f2d75bd216bf505de0d02fddef}`.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{ef29b8f2d75bd216bf505de0d02fddef}`
- **Flag Format Komunitas:** `CTF{ef29b8f2d75bd216bf505de0d02fddef}`
- **Verifikasi Live REST API CyLab:**
  Submisi ke `https://learn.cylabacademy.org/api/submissions/` mengembalikan respons status HTTP 201:
  `{"user": 1072359, "challenge": 746, "flag": "academy{ef29b8f2d75bd216bf505de0d02fddef}", "correct": true, "historical": false}`.
- **Verifikasi Simulasi Offline:** Skrip `scripts/solve_746_tea_cash.py` mengimplementasikan simulator memori heap `TeaCashSimulator` yang memvalidasi integritas 6 chunk 0x90 stride secara lokal dan mandiri.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Zeroization & Pembersihan Memori Sensitif Pasca-Pakai
Menyalin kredensial atau flag ke dalam heap chunk tanpa melakukan *zeroization* sebelum chunk dibebaskan meninggalkan artefak data di memori yang tidak teralokasi (*unallocated heap memory*). 
**Remediasi Defensif:**
Gunakan fungsi pembersihan memori aman yang kebal terhadap optimasi kompilator:
```c
/* Menggunakan explicit_bzero atau memset_s */
explicit_bzero((char*)chunks[CHUNK_COUNT-1] + FLAG_OFFSET, flen + 1);
```

### 2. Implementasi Safe-Linking Pointer Mangling
Pada implementasi modern glibc (versi 2.32 ke atas), glibc menyertakan mekanisme mitigasi *safe-linking* untuk pointer tcache dan fastbin:
$$P' = \left(\frac{L}{2^{12}}\right) \oplus P$$
di mana $L$ adalah alamat lokasi penyimpanan pointer dan $P$ adalah alamat target. Mekanisme ini mengacak pointer `fd` menggunakan entropy ASLR acak dari halaman memori tersebut, mencegah penyerang melakukan traversal atau pemalsuan pointer tcache tanpa mengetahui kebocoran heap base dan page offset secara bersamaan.

### 3. Eliminasi Information Disclosure Pointer Memori (ASLR Preservation)
Jangan pernah mencetak alamat pointer internal heap atau stack ke aliran keluaran pengguna (`printf("%p", ...)`). Mengungkapkan alamat internal secara langsung menggugurkan proteksi ASLR (*Address Space Layout Randomization*) pada sistem operasi modern.

### 4. Relevansi Modul Uji Kompetensi LKS Cyber Security
Pada skenario lomba LKS bidang *Binary Exploitation & Defensive Hardening*, pemahaman struktur data internal allocator Linux (tcache, fastbin, unsorted bin) sangat krusial baik untuk menganalisis celah *heap corruption* maupun saat melakukan re-engineering kode C untuk menutup potensi kebocoran data rahasia pada layanan daemon sistem.
