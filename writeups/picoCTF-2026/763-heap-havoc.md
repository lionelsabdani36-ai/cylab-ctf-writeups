# Writeup: Heap Havoc (Challenge ID: 763)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation
- **Difficulty:** Hard
- **Event:** picoCTF 2026
- **Points:** 200
- **Author:** Yahaya Meddy
- **Flag:** `academy{h34p_0v3rfl0w_95be5370}`

---

## Problem Statement & Scope

Peserta diberikan biner ELF 32-bit `vuln` dan berkas kode sumber `vuln.c`. Program menerima dua argumen nama dari baris perintah (`./vuln <name1> <name2>`). Di dalam memori, program mengalokasikan dua buah objek `struct internet`:
```c
struct internet {
    int priority;
    char *name;
    void (*callback)();
};
```
Masing-masing objek `i1` dan `i2` dialokasikan menggunakan `malloc(sizeof(struct internet))`, dan setiap buffer `name` dialokasikan sebesar 8 byte (`malloc(8)`). Program kemudian menyalin argumen pertama ke `i1->name` menggunakan `strcpy(i1->name, argv[1])` dan argumen kedua ke `i2->name` menggunakan `strcpy(i2->name, argv[2])`. Program memeriksa apakah `callback` terdefinisi dan memanggilnya jika ada. Terdapat fungsi tersembunyi `winner()` yang membuka `flag.txt` dan mencetak bendera rahasia.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Heap Buffer Overflow via Unbounded String Copy (CWE-120 / CWE-122):**
   Alokator memori heap mengalokasikan 8 byte untuk buffer string `i1->name`. Namun, `strcpy(i1->name, argv[1])` menyalin string masukan tanpa validasi panjang (`unbounded copy`). Masukan yang melebihi kapasitas buffer menulis melewati batas chunk alokasi heap (*heap boundary violation*), merusak metadata chunk berikutnya dan menimpa struktur objek `i2` yang berada tepat setelahnya di memori heap.

2. **Control Flow Hijacking via Function Pointer Overwrite (CWE-822):**
   Di memori heap 32-bit (ptmalloc2), urutan alokasi linier menghasilkan tata letak:
   - Chunk `i1`: ukuran 16 byte (offset +0x00)
   - Chunk `i1->name`: ukuran 16 byte (offset +0x10, user data pada +0x18)
   - Chunk `i2`: ukuran 16 byte (offset +0x20, user data pada +0x28)
   - Chunk `i2->name`: ukuran 16 byte (offset +0x30, user data pada +0x38)

   Jarak antara buffer `i1->name` dan awal user data objek `i2` adalah tepat 16 byte. Di dalam objek `i2`:
   - Offset +0 (jarak 16 byte dari `i1->name`): `int priority` (4 byte)
   - Offset +4 (jarak 20 byte dari `i1->name`): `char *name` (4 byte pointer)
   - Offset +8 (jarak 24 byte dari `i1->name`): `void (*callback)()` (4 byte pointer)

3. **Penyelamatan Pointer Tulis & Alamat Tetap (No PIE):**
   Karena `strcpy(i2->name, argv[2])` dieksekusi setelah `i1->name` meluap, pointer `i2->name` yang tertimpa harus diarahkan ke alamat memori yang valid dan dapat ditulisi (*writable memory*), seperti segmen `.bss` (`0x0804c040`). Jika pointer diarahkan ke alamat sembarang atau `NULL`, operasi `strcpy` kedua akan memicu *segmentation fault* sebelum pointer `callback` sempat dipanggil. Ketiadaan mitigasi PIE (*Position Independent Executable*) memungkinkan pemanfaatan alamat statis `winner()` pada `0x08049206`.

4. **NIST SP 800-115 Section 5.3 (System Flaw Identification):**
   Audit memori dinamis mengharuskan inspeksi terhadap heap layout, integritas metadata alokator, dan kepatuhan batas indeks buffer untuk mencegah arbitrary memory write dan control hijacking.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Mitigasi dan Simbol Biner:**
   Analisis menggunakan `readelf` dan `checksec`:
   - Arsitektur: Intel 80386 (ELF 32-bit LSB executable)
   - PIE: Disabled (Base `0x08048000`)
   - Canary: Disabled
   - NX: Enabled
   - Alamat `winner()`: `0x08049206`
   - Segmen `.bss` writable: `0x0804c040`

2. **Penyusunan Payload Eksploitasi:**
   Argumen pertama (`argv[1]`) disusun sebagai berikut:
   - 16 byte filler (`"A" * 16`) untuk mengisi sisa buffer `i1->name` dan header chunk `i2`.
   - 4 byte priority (`b"PRIO"`).
   - 4 byte pointer writable untuk `i2->name`: little-endian `0x0804c040` (`\x40\xc0\x04\x08`).
   - 4 byte pointer fungsi `winner()` untuk `i2->callback`: little-endian `0x08049206` (`\x06\x92\x04\x08`).
   - Total panjang payload `argv[1]`: 28 byte (tanpa karakter spasi atau byte null di tengah).

   Argumen kedua (`argv[2]`) diberikan string sembarang (`"junk"`), yang akan disalin ke alamat `.bss` tanpa menyebabkan tabrakan memori.

3. **Eksekusi Remote Terhadap Daemon Tantangan:**
   Menghubungkan soket TCP ke instans remote `chatelaine.cylabacademy.net`:
   ```bash
   python3 scripts/solve_763_heap_havoc.py
   ```
   Layanan memproses kedua argumen, mengeksekusi `i2->callback()` yang melompat ke `winner()`, dan mengembalikan bendera:
   `FLAG: academy{h34p_0v3rfl0w_95be5370}`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{h34p_0v3rfl0w_95be5370}`
- **Flag Komunitas:** `CTF{h34p_0v3rfl0w_95be5370}`
- **Bukti Validasi:** Live remote exploitation pada instans CyLab Security Academy berhasil membajak callback `i2` dan mengekstrak flag live secara deterministik (HTTP 201 `correct: true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Penggantian Fungsi Salin Tidak Aman (Secure String Copy):**
  Hindari penggunaan `strcpy()` pada buffer dengan panjang terbatas. Gunakan `strncpy()` atau fungsi yang memperhatikan ukuran buffer alokasi asli (`snprintf` atau `strlcpy`) dengan pembatasan ukuran `sizeof(dest)`.
- **Pemisahan Antara Buffer Data dan Pointer Kontrol:**
  Dalam desain struktur data di memori C/C++, pisahkan struktur yang memuat *function pointer* dari struktur yang memuat buffer dinamis yang dapat diisi oleh masukan pengguna. Tempatkan *function pointers* dalam struktur yang terisolasi atau di segmen memori read-only setelah inisialisasi.
- **Pengaktifan Mitigasi Biner Lengkap (Full Hardening):**
  Kompilasi seluruh biner dengan opsi `-fPIE -pie -Wl,-z,relro,-z,now` untuk mencegah pemanfaatan alamat absolut pada fungsi-fungsi internal program.
