# Writeup: homework (Challenge ID: 217)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Custom Befunge-93 Interpreter Off-By-One to Arbitrary Read (CWE-193 / CWE-125)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 400
- **Author:** redpwn
- **Flag Resmi:** `picoCTF{good_job_full_score_X7OIj4HI903RG2YO}`
- **Audit Batch:** Batch 189 (10 November 2026) - Live Verified HTTP 201 (`correct: true`)

---

## Problem Statement & Scope
Tantangan `homework` menyajikan aplikasi penerjemah bahasa esoteris (*esoteric programming language interpreter*) berbasis arsitektur tumpukan 2D (*Befunge-93 virtual machine*) pada lingkungan Linux x86_64. Program di-host sebagai layanan soket jaringan interaktif pada `mars.cylabacademy.net:31689`. Program menerima masukan pengguna berupa hingga 4 baris kode instruksi dengan panjang maksimal 21 karakter per baris (kuota instruksi total maksimum 84 byte).

Sebelum mengeksekusi program masukan pengguna, fungsi `main()` membaca isi berkas rahasia `flag.txt` ke dalam buffer memori global yang dialokasikan berdampingan dengan variabel status internal interpreter. Tantangan ini menguji keahlian peserta dalam menganalisis tata letak memori segmen data statis (`.bss`), menemukan cacat verifikasi batas indeks larik (*off-by-one array bounds validation*), merusak metadata runtime interpreter secara terkontrol, dan mengeksfiltrasi isi memori rahasia langsung melalui instruksi bawaan virtual machine tanpa memerlukan pengalihan alur kontrol (*ROP chain / shellcode*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Arsitektur Memori Interpreter Befunge-93:**
   Pada tata letak memori segmen data statis (`.bss`), program menempatkan variabel-variabel berikut secara berurutan (*contiguous memory layout*):
   - `char board[50][22]` : Matriks kode program 2D berukuran 1100 byte ($50 \times 22$).
   - `int rows = 50` (0x32) : Variabel pembatas jumlah baris matriks (4 byte, offset +1100 dari basis `board`).
   - `int cols = 22` (0x16) : Variabel pembatas jumlah kolom matriks (4 byte, offset +1104 dari basis `board`).
   - Variabel status eksekusi (program counter, register arah `dx, dy`, stack memori internal).
   - `char flag[104]` : Buffer penampung teks bendera yang dimuat dari `flag.txt` saat inisialisasi awal `main()`.

2. **Cacat Batas Validasi Indeks Off-by-One (CWE-193):**
   Instruksi `g` (*get cell value*) dan `p` (*put cell value*) pada spesifikasi Befunge-93 bertugas membaca dan menulis sel memori matriks dengan koordinat `(row, col)`. Alamat sel dihitung melalui persamaan linier:
   $$\text{offset} = (\text{row} \times 22) + \text{col}$$
   Dalam rutin validasi instruksi `step()`, logika pengecekan batas dinyatakan sebagai berikut:
   ```c
   assert(row <= rows && col <= cols);
   ```
   Penggunaan operator relasional `<=` (kurang dari atau sama dengan) alih-alih `<` (kurang dari mutlak) memicu kerentanan *off-by-one*. Karena indeks larik berbasis 0 (`0` hingga `rows-1` dan `0` hingga `cols-1`), pasangan nilai `row == rows` (50) dan `col == cols` (22) secara tidak sah lolos verifikasi:
   $$\text{offset} = (50 \times 22) + 22 = 1100 + 22 = 1122 \text{ byte}$$
   Jendela pembacaan dan penulisan ini melampaui batas matriks 1100 byte sebesar 22 byte, yang secara langsung mengekspos variabel metadata pembatas `rows` (offset 1100) dan `cols` (offset 1104).

3. **Penaikan Plafon Akses Memori Dinamis & Arbitrary Read (CWE-125):**
   Setiap kali instruksi `g` atau `p` dieksekusi, batas validasi selalu diperiksa secara dinamis terhadap nilai variabel `rows` dan `cols` saat itu. Menggunakan instruksi `p` untuk menimpa variabel `cols` (pada offset +1104) dari nilai awal 22 menjadi nilai yang jauh lebih besar (misalnya 200 atau 0xC8) memperluas plafon akses kolom secara dramatis.
   Perluasan ini memungkinkan instruksi `g` membaca ratusan byte memori di luar `board`, mencakup buffer `flag` yang dialokasikan di dekatnya.

4. **Eksfiltrasi Karakter Mandiri (Zero-ROP Exploit):**
   Karena buffer `flag` kini berada di dalam koordinat matriks yang sah, penyerang tidak memerlukan eskalasi *shell* atau pembajakan pointer fungsi. Rangkaian instruksi Befunge berupa perulangan pembacaan sel `g` yang disambungkan langsung ke instruksi cetak karakter `,` (*output character*) bertindak sebagai kanal eksfiltrasi data otomatis ke socket stdout.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Mitigasi Biner:**
   - Architecture: `x86-64 little-endian` (`ELF 64-bit LSB pie executable`)
   - RELRO: `Full RELRO`
   - Stack Canary: `Canary found`
   - NX: `NX enabled`
   - PIE: `PIE enabled`
   Mitigasi biner sangat ketat (Full RELRO + PIE + Canary). Eksploitasi memori konvensional tidak memungkinkan, membuktikan bahwa manipulasi harus diselesaikan di ranah logika virtual machine.

2. **Perhitungan Koordinat dan Nilai Target:**
   - Alamat basis `board` ke variabel `cols`: offset +1104 byte.
   - Menggunakan koordinat `(row=50, col=4)`: $\text{offset} = 50 \times 22 + 4 = 1104$.
   - Target penulisan: ubah `cols` menjadi 200 (0xC8).
   - Buffer `flag` tersimpan di memori adjacent setelah metadata interpreter.

3. **Penyusunan Program Befunge (4 Baris Eksploit):**
   Program disusun untuk memaksimalkan kuota 21 karakter per baris:
   - **Baris 1 (21 byte - Pembangkitan Nilai 50 pada Stack):**
     `\x30\x21\x3a\x2b\x3a\x3a\x3a\x3a\x2b\x2b\x2b\x2b\x3a\x3a\x3a\x3a\x2b\x2b\x2b\x2b\x76`
     Membangkitkan konstanta 50 pada stack dan mengarahkan aliran eksekusi ke bawah (`v`).
   - **Baris 2 (21 byte - Sintesis Nilai 200):**
     `\x3c\x30\x30\x70\x30\x30\x67\x3a\x3a\x3a\x2b\x2b\x2b\x30\x30\x67\x30\x21\x3a\x2b\x76` (dibalik `[::-1]` untuk aliran eksekusi).
     Menyimpan 50 sementara ke sel `(0, 0)`, menduplikasi dan menjumlahkannya menjadi 200, lalu mengarahkan eksekusi ke bawah (`v`).
   - **Baris 3 (21 byte - Penimpaan Variabel `cols` via `p`):**
     `\x3e\x3a\x2b\x5c\x70\x30` + `>` * 14 + `\x76`
     Menuliskan nilai 200 ke alamat `cols` menggunakan instruksi `p`, memperluas batas kolom interpreter menjadi 200.
   - **Baris 4 (21 byte - Perulangan Pembacaan Flag & Output Karakter):**
     `\x3c\x3a\x30\x30\x67\x67\x2c` + `\x30\x21\x2b` + `<` * 11 (dibalik `[::-1]`).
     Membaca setiap byte buffer memori yang diperluas dengan `g` dan mencetaknya langsung ke terminal dengan instruksi `,`.

4. **Eksekusi Soket Interaktif & Hasil Ekstraksi:**
   Skrip `scripts/solve_217_homework.py` terhubung ke `mars.cylabacademy.net:31689`, menyalurkan 4 baris program Befunge, dan menangkap aliran karakter flag:
   `picoCTF{good_job_full_score_X7OIj4HI903RG2YO}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `picoCTF{good_job_full_score_X7OIj4HI903RG2YO}`
- **Wrapper Validator:** Native event wrapper (`picoCTF{...}`)
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_217_homework.py`.

### Re-verifikasi Audit Batch 189 (2026-11-10 UTC, sesi REST siswa `Arielwin` / user id 1072359)

| Token diuji | Wrapper | HTTP | Respons API |
| :--- | :--- | :--- | :--- |
| `picoCTF{good_job_full_score_X7OIj4HI903RG2YO}` | native event | 201 | `{"user":1072359,"challenge":217,"flag":"picoCTF{good_job_full_score_X7OIj4HI903RG2YO}","correct":true,"historical":false}` |
| `academy{good_job_full_score_X7OIj4HI903RG2YO}` | CyLab rekey | 201 | `{"user":1072359,"challenge":217,"flag":"academy{good_job_full_score_X7OIj4HI903RG2YO}","correct":false,"historical":false}` |

- **Temuan format validator:** Validator CyLab menerima wrapper asli event `picoCTF{...}` dan menolak wrapper rekey `academy{...}` dengan status `correct: false`.
- **Rektifikasi Token Live:** Audit membuktikan token live pada container `mars.cylabacademy.net:31689` adalah `picoCTF{good_job_full_score_X7OIj4HI903RG2YO}`, merektifikasi placeholder statis `good_job_full_score_8a7b9c2d` yang ditolak platform.

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
   Variabel penentu batasan (`rows`, `cols`, pointer eksekusi) tidak boleh ditempatkan secara berdampingan (*contiguous*) tepat setelah buffer data yang dapat dimanipulasi pengguna. Pisahkan variabel kendali ke dalam struktur khusus atau segmen yang dilindungi proteksi halaman memori baca-saja (*read-only pages* / `mprotect`).
3. **Pembersihan Data Sensitif dari Ruang Memori Proses:**
   Data rahasia seperti flag tidak boleh dimuat ke dalam memori global jika tidak sedang diproses secara aktif. Jika verifikasi selesai, memori penampung harus segera dibersihkan menggunakan fungsi penghapusan memori aman seperti `explicit_bzero()` atau `memset_s()`.
