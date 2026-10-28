# 746 — tea-cash (Binary Exploitation, picoCTF 2026, Medium 100 pts)

- **ID / Event:** 746 / picoCTF 2026
- **Kategori / Tingkat:** Binary Exploitation / Medium
- **Flag:** `academy{ef29b8f2d75bd216bf505de0d02fddef}`
- **Status:** SOLVED 2026-10-28 (terverifikasi `POST /api/submissions/` -> `correct: true`)

## Deskripsi Skenario & Batasan Lingkungan
Biner `heapedit` (ELF x86-64, + `heapedit.c`, `libc.so.6`, `Makefile.share`
statis) mengalokasi 6 chunk 0x80, menyalin flag ke chunk ke-6 pada offset 8,
mencetak head free list, lalu meminta pengguna mengetik 6 alamat hasil
traversal. Lab on-demand via `nc chatelaine.cylabacademy.net 20716`.

## Teori & Akar Kerentanan (Root Cause)
1. **LIFO tcache glibc:** `free()` berurutan menautkan chunk lewat 8 byte
   pertama (fd pointer) dengan urutan terbalik: head = chunk[0] karena
   `free` dipanggil dari indeks 5 ke 0. Alamat diminta persis (`scanf %p`)
   lalu `memcpy(&next, user_addr, 8)` membaca pointer berikut.
2. **Stride heap deterministik:** 6 `malloc(0x80)` berurutan menghasilkan
   chunk berjarak 0x90 (0x80 user + 0x10 header metadata), sehingga
   traversal = `head + i*0x90`, tanpa perlu leak lanjutan.
3. Flag tersimpan plain di heap chunk terakhir; traversal benar mencetaknya.

## Rekonstruksi Pengujian Terstruktur
1. `PUT /api/challenges/746/instance/` -> poll hingga RUNNING; ambil port nc
   + unduh `heapedit`/`heapedit.c` dari CDN statis untuk audit source.
2. Analisis `heapedit.c`: `head = chunks[0]`, loop `free` mundur, validasi
   `scanf("%p")` per langkah.
3. Skrip socket: baca `tcache head -> 0x...`, kirim `head+i*0x90` (i=0..5);
   respons `Correct traversal! Flag: academy{ef29b8f2d75bd216bf505de0d02fddef}`.
4. Submit `POST /api/submissions/` -> HTTP 201 `correct: true`; `DELETE` slot instance.

## Token Validasi
`academy{ef29b8f2d75bd216bf505de0d02fddef}` — flag per-instance; solver
otomatis mengekstrak flag live dari layanan nc (bukan hardcode).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Jangan simpan rahasia plain di heap yang pointer internalnya diekspos ke
  pengguna; gunakan `mlock` + `memset` pasca-pakai dan pisahkan secret store.
- Validasi traversal saja tidak melindungi kerahasiaan bila layout heap
  deterministik — randomisasi/isolasi arena dan pointer mangling (safe-linking)
  menyulitkan prediksi.
- Latihan LKS: baca source + uji stride heap di GDB sebelum brute force alamat.
