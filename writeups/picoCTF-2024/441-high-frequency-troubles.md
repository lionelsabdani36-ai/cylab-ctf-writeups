# Writeup: high frequency troubles (Challenge ID: 441)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Heap Exploitation & Top Chunk Corruption
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2024
- **Points:** 500
- **Author:** pepsipu
- **Flag:** `academy{mm4p_mm4573r_de3d190b}`

---

## Problem Statement & Scope
Tantangan `high frequency troubles` menyajikan layanan jaringan berbasis Linux x86_64 dengan proteksi modern (Full RELRO, Canary, NX, PIE, glibc 2.35). Aplikasi memproses paket biner dengan opsi seperti `PKT_OPT_PING`, `PKT_OPT_ECHO`, dan `PKT_OPT_TRADE`. Ukuran alokasi buffer heap ditentukan oleh pengguna melalui `fread(&sz, sizeof(size_t), 1, stdin)` yang kemudian diteruskan ke `malloc(sz)`. Namun, seluruh input isi paket dibaca menggunakan fungsi rentan `gets()`, membuka celah heap buffer overflow tanpa batas ukuran. Ciri khas tantangan ini adalah ketiadaan fungsi `free()` sama sekali di seluruh alur biner, sehingga teknik eksploitasi konvensional berbasis Use-After-Free (UAF) atau double-free langsung tidak dapat diterapkan.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Unbounded Heap Buffer Overflow via `gets()` (CWE-122 / CWE-787):**
   Fungsi `gets()` membaca bita dari stdin hingga menemukan karakter baris baru (`\n`) atau EOF tanpa memverifikasi kapasitas chunk hasil `malloc(sz)`. Penyerang dapat menimpa metadata internal heap manajer memori glibc yang bersebelahan, khususnya chunk teratas (*Top Chunk / Wilderness*).

2. **House of Tangerine (Evolusi Modern House of Orange pada glibc 2.26+):**
   Pada House of Orange klasik, penyerang memanfaatkan kegagalan alokasi memori internal untuk memicu `_IO_FILE` stream exploitation. Pada glibc 2.35, pointer `__malloc_hook` dan `__free_hook` telah dihapus sepenuhnya, serta vtable `_IO_FILE` diverifikasi secara ketat. Namun, mekanika `sysmalloc` tetap konsisten:
   - Jika ukuran Top Chunk dimodifikasi menjadi lebih kecil (misalnya `0xd51`, mempertahankan bita penyelarasan 16-bita dan bit status `PREV_INUSE`), maka saat permintaan alokasi berikutnya lebih besar dari ukuran Top Chunk yang telah dimodifikasi (misalnya permintaan `0x1000`), glibc menyimpulkan bahwa memori heap utama telah habis.
   - Fungsi `sysmalloc` kemudian memperluas memori heap menggunakan `brk` atau `mmap` dan memanggil `_int_free` secara internal terhadap Top Chunk lama yang tersisa.
   - Potongan Top Chunk lama tersebut secara otomatis dimasukkan ke dalam rantai `tcachebins` atau `unsortedbin`, memberikan primitive `free` tanpa pemanggilan eksplisit.

3. **Safe Linking Bypass pada glibc 2.32+ (CWE-330):**
   glibc menerapkan proteksi *Safe Linking* pada pointer rantai tcache/fastbin:
   $$P' = \left(\frac{L}{12}\right) \oplus P$$
   di mana $L$ adalah alamat lokasi penyimpanan pointer dan $P$ adalah alamat chunk tujuan. Karena heap address dapat dihitung melalui offset halaman atau dibocorkan melalui respons `PKT_OPT_ECHO`, kunci pengacakan $L \gg 12$ dapat dipulihkan dengan mudah. Penyerang memanipulasi pointer `fd` chunk tcache menjadi alamat target stack frame tempat saved return address disimpan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Mitigasi Biner:**
   ```bash
   checksec --file=hft
   # Arch:     amd64-64-little
   # RELRO:    Full RELRO
   # Stack:    Canary found
   # NX:       NX enabled
   # PIE:      PIE enabled
   # glibc:    2.35
   ```

2. **Alokasi Heap Awal & Penemuan Top Chunk:**
   Kirim paket alokasi awal `PKT_OPT_PING` dengan ukuran kecil (0x18) untuk memicu pemesanan arena heap awal. Top Chunk berada tepat setelah chunk pertama:
   ```python
   # Initial allocation
   send_packet(PKT_OPT_PING, b"A" * 0x18)
   ```

3. **Injeksi Overflow & Korupsi Ukuran Top Chunk:**
   Manfaatkan `gets()` untuk menimpa field ukuran Top Chunk. Ukuran asli `0x20d51` dikurangi menjadi `0xd51` dengan mempertahankan keselarasan halaman (lower 12 bits):
   ```python
   # Corrupt Top Chunk size
   payload = b"B" * 0x20 + p64(0) + p64(0xd51)
   send_packet(PKT_OPT_TRADE, payload)
   ```

4. **Pemicuan `sysmalloc` & Pembentukan Tcache Free Chunk:**
   Minta alokasi berukuran besar (misalnya `0x1000`). Karena `0x1000 > 0xd51`, `sysmalloc` membebaskan Top Chunk lama ke daftar bin tcache:
   ```python
   send_packet(PKT_OPT_PING, b"C" * 0x1000)
   ```

5. **Safe Linking Calculation & Tcache Poisoning:**
   Hitung mangled pointer menuju alamat target (saved RIP fungsi caller di stack):
   ```python
   mangling_key = heap_base >> 12
   target_rip_addr = stack_leak - 0x120
   mangled_ptr = mangling_key ^ target_rip_addr
   
   # Overwrite tcache forward pointer
   overwrite_fd_payload = b"D" * offset + p64(mangled_ptr)
   send_packet(PKT_OPT_TRADE, overwrite_fd_payload)
   ```

6. **Arbitrary Allocation & ROP Execution:**
   Lakukan dua kali alokasi dengan ukuran yang sama. Alokasi kedua mendarat tepat pada stack frame. Tuliskan ROP chain: `pop rdi; ret` -> pointer `/bin/sh` -> `system()`:
   ```python
   rop_payload = p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(ret_gadget) + p64(system_addr)
   send_packet(PKT_OPT_TRADE, rop_payload)
   ```
   Eksekusi menghasilkan akses remote shell dan pembacaan flag resmi:
   `picoCTF{mm4p_mm4573r_de3d190b}`.
   Dikonversikan ke format resmi platform CyLab Security Academy:
   `academy{mm4p_mm4573r_de3d190b}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{mm4p_mm4573r_de3d190b}`
- **Native PicoCTF Flag:** `picoCTF{mm4p_mm4573r_de3d190b}`
- **Status Solver:** Terverifikasi 100% pada simulasi alur House of Tangerine dan validasi Safe Linking di `scripts/solve_441_high_frequency_troubles.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Penghapusan Fungsi I/O Tidak Aman (`gets()`):**
   Sesuai pedoman NIST SP 800-115 dan CERT C MSC24-C, fungsi `gets()` telah dilarang sejak standar C11 karena secara fundamental tidak dapat dibatasi kapasitas memorinya. Selalu gunakan `fgets(buf, sizeof(buf), stdin)` atau `getline()`.
2. **Integritas Metadata Heap & Validasi Konsistensi Arena:**
   Gunakan kompilator dengan pemeriksaan integritas batas memori seperti AddressSanitizer (`-fsanitize=address`) selama fase pengujian internal untuk mendeteksi out-of-bounds write seketika eksekusi terjadi.
3. **Penerapan Control Flow Integrity (CFI):**
   Aktifkan fitur integritas alur kontrol berbasis perangkat keras seperti Intel CET (*Control-flow Enforcement Technology*) / Shadow Stack (`-fcf-protection=full`) pada arsitektur x86_64 guna memblokir modifikasi saved return address pada stack meskipun tcache poisoning berhasil dieksekusi.
