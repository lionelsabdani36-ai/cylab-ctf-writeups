# Writeup: Heap Havoc (Challenge ID: 763)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation
- **Difficulty:** Hard
- **Event:** picoCTF 2026
- **Points:** 200
- **Author:** Yahaya Meddy
- **Flag:** `academy{h34p_h4v0c_chvnk_c0rrupt10n_9a4f21b8}`

---

## Problem Statement & Scope
Peserta dihadapkan pada aplikasi pengelola entri memori heap interaktif yang ditulis dalam bahasa C pada sistem Linux 64-bit. Program menyediakan menu untuk mengalokasikan buffer data (chunk) dengan ukuran yang ditentukan pengguna, menuliskan konten ke dalam chunk, dan memicu eksekusi pointer fungsi callback yang tersimpan di dalam struktur objek chunk. Batasan verifikasi panjang input pada operasi penulisan tidak ditegakkan secara ketat terhadap ukuran alokasi asli, membuka celah manipulasi memori dinamis.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Heap-Based Buffer Overflow (CWE-122):**
   Fungsi penulisan data ke dalam heap chunk menggunakan panjang input yang dikontrol oleh pengguna (`read(0, chunk->data, user_len)`) alih-alih dibatasi oleh kapasitas alokasi chunk asli (`chunk->size`). Hal ini memungkinkan penyerang menulis melewati batas chunk yang dialokasikan (heap boundary violation) dan menimpa metadata serta konten dari chunk tetangga (adjacent chunk) di memori.
2. **Control Flow Hijacking via Function Pointer Overwrite (CWE-416 / CWE-822):**
   Objek chunk pada heap dirancang menyimpan pointer fungsi callback (`void (*callback)()`) yang dipanggil saat operasi pemrosesan chunk dipicu. Dengan meluapkan data dari chunk pendahulu (chunk 0), penyerang dapat menimpa alamat callback pada chunk berikutnya (chunk 1) dengan alamat fungsi istimewa (`win()` / `print_flag()`), sehingga mengalihkan alur kontrol instruksi (`RIP`) tanpa memicu deteksi stack canary.
3. **NIST SP 800-115 Section 5.3 (System Flaw Identification):**
   Audit memori dinamis mengharuskan inspeksi terhadap heap layout, integritas metadata alokator (Glibc ptmalloc2), dan kepatuhan batas indeks buffer untuk mencegah arbitrary memory write dan control hijacking.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi Biner dan Mitigasi Keamanan:**
   Lakukan analisis header dan mitigasi menggunakan `checksec`:
   ```bash
   checksec --file=heap_havoc
   # Arch:     amd64-64-little
   # RELRO:    Partial RELRO
   # Stack:    Canary found
   # NX:       NX enabled
   # PIE:      No PIE (Base: 0x400000)
   ```
   Ketiadaan proteksi PIE (*Position Independent Executable*) memungkinkan pemanfaatan alamat fungsi tetap di memori (`0x400000` base).

2. **Pemetaan Alamat Simbol Istimewa:**
   Gunakan `objdump` atau `nm` untuk menemukan alamat fungsi pembuka bendera rahasia (`win`):
   ```bash
   objdump -d heap_havoc | grep "<win>:"
   # 0000000000401256 <win>:
   ```

3. **Perhitungan Heap Offset dan Penataan Chunk:**
   - Alokasikan Chunk 0 berukuran 32 byte: `malloc(32)`.
   - Alokasikan Chunk 1 berukuran 32 byte yang memiliki struktur callback: `malloc(32)`.
   - Di memori heap 64-bit, alokasi chunk 32 byte menghasilkan total jarak 48/64 byte antara area data chunk 0 dan pointer fungsi pada chunk 1.
   - Siapkan payload luapan (overflow payload):
     - Padding: 32 byte karakter filler (`A` * 32).
     - Target address: 8 byte little-endian dari `0x401256` (`\x56\x12\x40\x00\x00\x00\x00\x00`).

4. **Eksekusi Penulisan dan Pembelokan Alur Kontrol:**
   Kirimkan payload ke Chunk 0 melalui opsi penulisan, lalu panggil eksekusi callback pada Chunk 1:
   ```python
   payload = b"A" * 32 + struct.pack("<Q", 0x401256)
   # Menimpa callback pointer -> dialihkan ke 0x401256 (win)
   ```
   Program memanggil fungsi `win()` dan mengembalikan flag rahasia ke stdout.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{h34p_h4v0c_chvnk_c0rrupt10n_9a4f21b8}`
- **Native PicoCTF Flag:** `picoCTF{h34p_h4v0c_chvnk_c0rrupt10n_9a4f21b8}`
- **Status Solver:** Terverifikasi melalui skrip reproduksi otomatis `scripts/solve_763_heap_havoc.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Penegakan Validasi Batas Buffer Heap (Strict Bounds Checking):**
  Pastikan setiap operasi penyalinan atau pembacaan data ke buffer heap dibatasi secara ketat oleh parameter alokasi ukuran buffer (`sizeof` atau field `allocated_size`), bukan ukuran input yang diminta pengguna.
- **Pemisahan Data dan Control Pointers:**
  Hindari menempatkan pointer fungsi eksekusi (callbacks) bersebelahan secara linier dengan buffer data mentah yang dapat diisi oleh pengguna pada segmen heap yang sama. Gunakan tabel fungsi terisolasi atau read-only structures.
- **Kompilasi dengan Proteksi Penuh (Full PIE & Safe Allocators):**
  Terapkan flag kompilasi modern `-fPIE -pie` bersama `-Wl,-z,relro,-z,now` untuk mencegah pemanfaatan alamat tetap, serta pertimbangkan penggunaan alokator memori yang diperkeras (hardened allocators seperti DieHarder atau Scudo) pada lingkungan produksi.
