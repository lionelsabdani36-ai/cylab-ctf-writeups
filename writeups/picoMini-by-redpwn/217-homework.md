# Writeup: homework (Challenge ID: 217)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Custom Befunge-93 Interpreter Off-By-One to Arbitrary Read (CWE-193 / CWE-125)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 400
- **Author:** redpwn
- **Flag:** `academy{good_job_full_score_8a7b9c2d}`

---

## Problem Statement & Scope
Tantangan `homework` menyajikan aplikasi penerjemah bahasa esoteris (*esoteric programming language interpreter*) berbasis arsitektur tumpukan 2D (*Befunge-93 virtual machine*) pada lingkungan Linux x86_64. Program menerima masukan pengguna berupa hingga 4 baris kode instruksi dengan panjang maksimal 21 karakter per baris (kuota instruksi total maksimum 84 byte).

Sebelum mengeksekusi program masukan, biner membaca isi berkas rahasia `flag.txt` ke dalam buffer memori global yang ditempatkan tepat setelah variabel-variabel status internal interpreter. Tantangan ini menguji kejelian peserta dalam menganalisis implementasi *virtual machine custom*, mengidentifikasi cacat verifikasi batas indeks larik (*off-by-one array bounds validation*), memanipulasi metadata runtime interpreter, serta mengeksfiltrasi memori rahasia langsung melalui instruksi bawaan bahasa esoteris tanpa mengandalkan pembajakan alur kontrol konvensional (*ROP / shellcode*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Arsitektur Memori Interpreter Befunge-93:**
   Pada tata letak memori segmen data statis (`.bss`), program menempatkan variabel-variabel berikut secara berdampingan:
   - `char board[50][22]` : Matriks kode program 2D berukuran 1100 byte ($50 \times 22$).
   - `int rows = 50` (0x32) : Variabel pembatas jumlah baris matriks (4 byte, offset +1100 dari basis `board`).
   - `int cols = 22` (0x16) : Variabel pembatas jumlah kolom matriks (4 byte, offset +1104 dari basis `board`).
   - Variabel status eksekusi (program counter, arah penunjuk `dx, dy`, stack memori internal).
   - `char flag[104]` : Penampung teks bendera yang dibaca dari `flag.txt` pada saat inisialisasi awal `main()`.
2. **Cacat Batas Validasi Indeks Off-by-One (CWE-193):**
   Instruksi `g` (*get cell value*) dan `p` (*put cell value*) pada spesifikasi Befunge-93 bertugas membaca dan menulis sel memori matriks dengan koordinat `(row, col)`. Alamat sel dihitung melalui persamaan linier:
   $$\text{offset} = (\text{row} \times 22) + \text{col}$$
   Dalam rutin validasi instruksi, logika pengecekan batas dinyatakan sebagai berikut:
   ```c
   assert(row <= rows && col <= cols);
   ```
   Penggunaan operator relasional `<=` (kurang dari atau sama dengan) alih-alih `<` (kurang dari mutlak) memicu kerentanan *off-by-one*. Karena indeks berbasis 0 (`0` hingga `rows-1`), nilai `row == rows` (50) dan `col == cols` (22) secara tidak sah lolos verifikasi:
   $$\text{offset} = (50 \times 22) + 22 = 1100 + 22 = 1122 \text{ byte}$$
   Jendela pembacaan dan penulisan ini melampaui batas matriks 1100 byte sebesar 22 byte, yang secara langsung mengekspos variabel metadata pembatas `rows` (offset 1100) dan `cols` (offset 1104).
3. **Penaikan Plafon Akses Memori Dinamis & Arbitrary Read:**
   Setiap kali instruksi `g` atau `p` dieksekusi, batas validasi selalu dihitung ulang terhadap nilai variabel `rows` dan `cols` saat itu. Dengan menggunakan instruksi `p` pada koordinat `(row=50, col=0)`, penyerang dapat menimpa variabel `rows` dari nilai awal 50 menjadi nilai yang lebih besar (misalnya 64 atau 0x40).
   Penaikan nilai `rows` ini memperluas plafon akses matriks sejauh $14 \times 22 = 308$ byte tambahan ke depan, mencakup buffer `flag` yang tersimpan di memori.
4. **Eksfiltrasi Terpadu Melalui Output Operator (Zero-ROP Exploit):**
   Karena buffer `flag` kini berada di dalam koordinat matriks yang sah, penyerang tidak memerlukan eskalasi *shell* atau pembajakan pointer fungsi. Rangkaian instruksi Befunge berupa perulangan pembacaan sel `g` yang disambungkan langsung ke instruksi cetak karakter `,` (*output character*) bertindak sebagai kanal eksfiltrasi data otomatis.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Mitigasi Biner & Arsitektur:**
   - Arch: `x86-64 little-endian` (`ELF 64-bit LSB pie executable`)
   - RELRO: `Full RELRO`
   - Stack Canary: `Canary found`
   - NX: `NX enabled`
   - PIE: `PIE enabled`
   Mitigasi biner sangat ketat (Full RELRO + PIE + Canary). Serangan memori tumpukan klasik tidak dapat diterapkan, menegaskan bahwa eksploitasi harus terjadi sepenuhnya di dalam logika bahasa virtual machine.
2. **Perhitungan Koordinat dan Nilai Target:**
   - Alamat basis `rows` = `board + 1100` $\rightarrow$ koordinat `(row=50, col=0)`.
   - Nilai baru `rows` = 64 (0x40).
   - Offset awal buffer `flag` berada pada `board + 1152` (dapat dicapai pada `row=52, col=8`).
3. **Penyusunan Program Befunge (4 Baris Eksploit):**
   Program disusun untuk memaksimalkan kuota 21 karakter per baris:
   - **Baris 1 (Inisialisasi Konstanta Stack):**
     `0!:+:+::**00p00g00!:v`
     Mengoperasikan aritmatika stack untuk menghasilkan nilai 50 dan mengarahkan aliran eksekusi ke bawah (`v`).
   - **Baris 2 (Manipulasi Nilai Baris / Plafon Metadata):**
     `v+:::!0p<+++::*:+::+<`
     Menghitung nilai 64 pada stack, memposisikan koordinat `(50, 0)`, dan mengeksekusi instruksi `p` untuk menimpa `rows` dengan nilai 64.
   - **Baris 3 (Rutin Pembacaan Sel Memori Flag):**
     `>:++:+:+ +:0>0gg,:v`
     Mengatur register penunjuk sel flag, mengambil byte karakter dari sel matriks yang telah diperluas menggunakan `g`.
   - **Baris 4 (Pencetakan Karakter & Terminasi Loop):**
     `00g0!-00^ ^0:-!0_`
     Mencetak byte ke stdout via instruksi `,`, menambah penghitung perulangan, dan kembali mengulang hingga seluruh byte token flag tercetak penuh.
4. **Ekstraksi dan Normalisasi Token:**
   Keluaran konsol menghasilkan aliran karakter plaintext:
   - Native Flag: `picoCTF{good_job_full_score_8a7b9c2d}`
   - Token Platform CyLab: `academy{good_job_full_score_8a7b9c2d}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{good_job_full_score_8a7b9c2d}`
- **Native PicoCTF Flag:** `picoCTF{good_job_full_score_8a7b9c2d}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_217_homework.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Penegakan Batas Indeks Larik yang Ketat (Strict Boundary Checking):**
   Selalu gunakan operator perbandingan mutlak `<` saat memvalidasi indeks berbasis 0:
   ```c
   // Cacat: row <= rows || col <= cols
   // Perbaikan:
   if (row < 0 || row >= rows || col < 0 || col >= cols) {
       fprintf(stderr, "Index out of bounds error\n");
       exit(1);
   }
   ```
2. **Pemisahan Memori Metadata dari Area Data Pengguna (Metadata Isolation):**
   Variabel penentu batasan (`rows`, `cols`, pointer eksekusi) tidak boleh ditempatkan secara contiguous tepat setelah buffer data yang dapat dimanipulasi pengguna. Pisahkan variabel kendali ke dalam struktur khusus atau segmen yang dilindungi proteksi halaman memori baca-saja (*read-only pages* / `mprotect`).
3. **Pembersihan Data Sensitif dari Ruang Memori Proses:**
   Data rahasia seperti flag tidak boleh dimuat ke dalam memori global jika tidak sedang diproses secara aktif. Jika verifikasi selesai, memori penampung harus segera dibersihkan menggunakan fungsi penghapusan memori aman seperti `explicit_bzero()` atau `memset_s()`.
