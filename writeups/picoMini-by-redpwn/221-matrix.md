# Writeup: MATRIX (Challenge ID: 221)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Custom Stack-Based VM & Bytecode State Traversal (CWE-829 / CWE-670)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 500
- **Author:** asphyxia
- **Flag:** `academy{y0uv3_3sc4p3d_th3_m4ze...f0r_n0w-hYkq2D9PmrA5GpEq}`

---

## Problem Statement & Scope
Tantangan `MATRIX` menyajikan berkas biner ELF Linux 64-bit stripped (`x86_64-64-little`). Deskripsi tantangan sangat sederhana: *"Escape the matrix."*. Ketika biner dieksekusi secara interaktif, program tidak meminta string password standar, melainkan menerima karakter navigasi arah `u` (up), `d` (down), `l` (left), dan `r` (right) satu per satu. Pengguna dituntut untuk menavigasi sebuah labirin tersembunyi yang disimulasikan di dalam memori program. Jika navigasi gagal, keluar batas, atau kehabisan poin kesehatan saat menembus pos pemeriksaan (*checkpoints*), program terminasi secara hening (*silent exit*) tanpa mencetak petunjuk apa pun. Biner dikompilasi dengan Partial RELRO, Stack Canary, NX, dan No PIE. Peserta harus membongkar arsitektur mesin virtual internal, memetakan aturan labirin, dan menyusun sekuens input yang valid untuk mencapai sel keluar dan mengekstraksi flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pola Obfuscasi Mesin Virtual Berbasis Stack (Custom Stack-Based VM):**
   Alih-alih menggunakan instruksi native x86_64 untuk logika verifikasi, pengembang membangun sebuah interpreter bytecode kustom di dalam biner. Interpreter ini memiliki:
   - *Instruction Pointer* (PC) virtual yang membaca deretan opcode dari segmen `.rodata`.
   - *Data Stack* virtual untuk manipulasi operan matematika.
   - Register internal untuk posisi koordinat agen `(X, Y)` dan akumulator kesehatan (*Health Points* / HP).
2. **Keterbatasan Analisis Statis String (*Dynamic Character Assembly*):**
   Flag tidak tersimpan dalam bentuk string statis di dalam berkas biner (`strings` hanya menampilkan nama simbol libc). Flag didefinisikan sebagai serangkaian operan numerik yang ditransformasikan secara dinamis melalui operasi aritmatika VM saat kondisi kemenangan (*win condition*) terpenuhi, lalu dicetak karakter-per-karakter melalui opcode keluaran `putchar`.
3. **Pemodelan State Ruang Keadaan (*State-Space Breadth-First Search*, BFS):**
   Labirin virtual mengimplementasikan aturan matriks 2D dengan beberapa jenis sel khusus:
   - Sel biasa: Mengizinkan pergerakan jika bukan dinding.
   - Sel penambah HP (`^`): Menambahkan nilai HP agen.
   - Sel pos pemeriksaan (*checkpoint*): Memeriksa apakah agen memiliki HP minimal $\ge 5$. Jika HP kurang, eksekusi VM langsung dihentikan.
   - Sel keluar (`$`): Memicu rutinitas pencetakan flag jika dan hanya jika tercapai dalam kondisi state valid.
   Rute geometris terpendek (*shortest path*) dari titik awal ke sel `$` selalu gagal karena melewati terlalu sedikit sel `^`, sehingga agen kekurangan HP saat menemui checkpoint. Oleh karena itu, lintasan yang benar mengharuskan agen bergerak bolak-balik (*oscillating*) di baris-baris awal (`rlrl...`) untuk mengumpulkan HP cadangan sebelum melintasi pos pemeriksaan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Reverse Engineering Dispatcher Mesin Virtual:**
   Melalui analisis Ghidra, loop utama interpreter ditemukan pada fungsi evaluasi bytecode. Pemetaan opcode instruksi virtual menghasilkan:
   - `0x01` - `0x04`: Navigasi posisi (atas, bawah, kiri, kanan).
   - `0x10`: Pengecekan tabrakan dinding (*wall collision test*).
   - `0x20`: Pengambilan tile spesial dan pembaruan counter HP.
   - `0x30`: Validasi ambang batas checkpoint HP.
   - `0x40`: Rutinitas terminasi sukses dan pencetakan flag loop.
2. **Ekstraksi Peta Labirin & Penentuan Lintasan Valid:**
   Setelah tata letak labirin di-dump dari memori, graf pergerakan dimodelkan dengan tuple state `(x, y, hp)`. Algoritma pencarian graf mengidentifikasi kebutuhan akumulasi HP di area awal. Sekuens pergerakan yang memenuhi seluruh 5 checkpoint dan mencapai exit ditemukan:
   ```text
   rrrrrlrlrlrlrllddddddlddrrddrrrdrddrruuuruuuuuuurrddddddddlddrd
   ```
   (Total 63 langkah terarah).
3. **Eksekusi Eksploitasi Otomatis via Pipa Input:**
   Sekuens input dialirkan langsung ke standar input biner:
   ```bash
   echo 'rrrrrlrlrlrlrllddddddlddrrddrrrdrddrruuuruuuuuuurrddddddddlddrd' | ./matrix
   ```
   VM memproses setiap langkah secara berurutan:
   - Langkah 1–16: Mengumpulkan HP dari sel `^` melalui pergerakan bolak-balik kanan-kiri.
   - Langkah 17–62: Melewati pos pemeriksaan 1 sampai 5 dengan HP aman di atas ambang batas.
   - Langkah 63: Memasuki sel exit `$`.
4. **Hasil Verifikasi Flag:**
   VM mengeksekusi loop output dan memancarkan string flag:
   `picoCTF{y0uv3_3sc4p3d_th3_m4ze...f0r_n0w-hYkq2D9PmrA5GpEq}` dinormalisasi ke token resmi CyLab: `academy{y0uv3_3sc4p3d_th3_m4ze...f0r_n0w-hYkq2D9PmrA5GpEq}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{y0uv3_3sc4p3d_th3_m4ze...f0r_n0w-hYkq2D9PmrA5GpEq}`
- **Native PicoCTF Flag:** `picoCTF{y0uv3_3sc4p3d_th3_m4ze...f0r_n0w-hYkq2D9PmrA5GpEq}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_221_matrix.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Analisis Malware Obfuscated Berbasis VM (Reverse Engineering LKS):**
   Teknik mesin virtual kustom adalah mekanisme proteksi kode nyata yang sering digunakan oleh *packer* komersial (seperti VMProtect / Themida) dan malware canggih untuk mengelabui deteksi berbasis tanda tangan (*signature-based AV*). Kompetensi LKS menuntut kemampuan mengisolasi dispatcher loop dan memetakan ISA virtual menjadi representasi tingkat tinggi.
2. **Validasi State Deterministik vs Keamanan Kriptografis (NIST SP 800-115 §5.4):**
   Mengandalkan kerumitan logika labirin atau teka-teki keadaan (*security through obscurity*) tidak memberikan jaminan kerahasiaan data. Setelah interpreter berhasil dimodelkan, pemecahan masalah direduksi menjadi penelusuran graf deterministik (BFS). Proteksi rahasia harus selalu didasarkan pada skema enkripsi terstandarisasi (AES-GCM, ChaCha20-Poly1305) dengan manajemen kunci terisolasi pada perangkat keras (TPM / HSM).
3. **Pengerasan Biner & Integritas Aliran Kontrol (CFI):**
   Terapkan *Control Flow Guard* (CFG) atau *Control-flow Enforcement Technology* (Intel CET) serta kompilasi biner dengan Full RELRO dan PIE untuk mempersulit analisis alur eksekusi taktis:
   ```bash
   gcc -fPIE -pie -Wl,-z,relro,-z,now -fcf-protection=full -o secure_matrix matrix.c
   ```
