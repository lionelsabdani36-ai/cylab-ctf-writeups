# Writeup: Stonk Market (Challenge ID: 164)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Heap Format String & GOT Hijacking via Stack Pivoting
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 180
- **Author:** madStacks
- **Flag:** `academy{explo1t_m1t1gashuns_7838034c}`

---

## Problem Statement & Scope
Tantangan `Stonk Market` menyajikan aplikasi simulasi bursa saham yang merupakan sekuel lanjutan dari tantangan populer `Stonks`. Berbeda dengan varian sebelumnya di mana bendera (*flag*) dimuat langsung ke memori stack, pada tantangan ini pengembang secara eksplisit telah menghapus pembacaan token bendera ke memori stack. Pengguna dituntut untuk mendapatkan eksekusi kode arbitrer (*arbitrary remote code execution*) guna memunculkan subshell interaktif.

Tujuan utama dari tantangan ini adalah mengaudit biner ELF 64-bit (`vuln`), mengidentifikasi celah kerentanan format string pada buffer alokasi heap, merekayasa teknik penulisan memori berantai (*chained format string writes*) menggunakan pointer bersarang pada stack, menimpa tabel tautan dinamis Global Offset Table (`free@got`) agar mengarah ke `system@plt`, dan menyuntikkan argumen perintah shell untuk mengekstrak isi `flag.txt`.

Ruang lingkup audit keamanan kepatuhan **NIST SP 800-115 Section 4.2** (*Binary and Software Security Assessment*):
1. Verifikasi mitigasi biner ELF: Partial RELRO, Stack Canary aktif, NX aktif, No PIE (Base statis `0x400000`).
2. Analisis siklus hidup alokasi heap pada fungsi `buy_stonks()` dan eksekusi `printf(user_buf)`.
3. Pemetaan parameter posisi format string x86-64 (register RDI, RSI, RDX, RCX, R8, R9 dan offset stack argument).
4. Pemilihan pointer stack perantara (*stack scratchpad pointer / saved RBP*) untuk penulisan alamat target GOT.
5. Pembajakan entri GOT fungsi dealokasi `free` dan eksekusi perintah shell `system("sh")`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Injeksi Format String Heap (CWE-134)
Pada fungsi `buy_stonks()`, masukan token API dibaca ke dalam memori heap menggunakan `scanf`:
```c
char *user_buf = malloc(300 + 1);
printf("What is your API token?\n");
scanf("%300s", user_buf);
printf("Buying stonks with token:\n");
printf(user_buf);
```
Pengembang langsung melewatkan pointer heap `user_buf` sebagai argumen pertama fungsi `printf` tanpa string format statis (misalnya `printf("%s", user_buf)`). Akibatnya, masukan pengguna yang mengandung penentu format (*format specifiers*) seperti `%x`, `%p`, dan `%n` dievaluasi oleh fungsi `printf`.

### 2. Penulisan Memori Arbitrer Tanpa Input di Stack (CWE-123)
Pada tantangan format string standar, string format berada di stack sehingga penyerang dapat menempatkan alamat target langsung di awal buffer dan merujuknya menggunakan indeks posisi (misalnya `%8$n`). Namun dalam kasus `Stonk Market`, buffer masukan berada di heap:
- Penyerang tidak dapat langsung merujuk buffer input sebagai argumen penulisan `%n`.
- Solusinya adalah memanfaatkan pointer yang sudah ada di stack yang mengarah ke stack itu sendiri (*pointer to stack*).
- Pada frame fungsi `buy_stonks`, argumen ke-12 memuat nilai *saved RBP*, yang menunjuk ke alamat frame stack argumen ke-20.
- Dengan menuliskan alamat `free@got` (`0x602018`) ke argumen ke-12 menggunakan `%n`, alamat target berhasil ditanamkan ke dalam stack pada argumen ke-20. Selanjutnya, argumen ke-20 dapat digunakan dengan penentu format `%20$hhn` untuk menuliskan byte ke alamat `free@got`.

---

## Tahapan Eksploitasi & Verifikasi (Reproduction Steps)

1. **Pemetaan Simbol dan Alamat Statis Biner:**
   - Karena biner dikompilasi tanpa PIE (*Position Independent Executable*) dan menggunakan Partial RELRO:
     - `free@got` = `0x602018`
     - `system@plt` = `0x4006f0`
     - Entri awal `free@got` menunjuk ke resolusi stub PLT `0x4006c6`.
     - Cukup menimpa 1 byte terendah (*low byte*) dari `free@got` dari `0xc6` menjadi `0xf0` untuk mengalihkannya ke `system@plt`.

2. **Penyusunan Format String Tiga Tahap:**
   Format string disusun dalam satu pemanggilan terpadu:
   ```text
   %c%c%c%c%c%c%c%c%c%c%6299662c%n%216c%20$hhn%10504067c%18$n
   ```
   - **Tahap A (Tulis Alamat free@got ke Stack Scratchpad):**
     Mencetak 10 karakter tunggal `%c` lalu melakukan padding `6299662` karakter (total karakter dicetak = `0x602018`). Penentu `%n` (argumen 12 / saved RBP) menuliskan nilai `0x602018` ke lokasi memori yang menjadi argumen ke-20.
   - **Tahap B (Alihkan free@got ke system@plt):**
     Mencetak tambahan 216 karakter untuk mengubah byte terendah running count menjadi `0xf0`. Penentu posisi `%20$hhn` menuliskan 1 byte `0xf0` ke alamat yang ditunjuk oleh argumen ke-20 (`free@got`), menimpa fungsi `free` menjadi `system`.
   - **Tahap C (Suntikkan Argumen "sh" ke Pointer Portfolio):**
     Mencetak tambahan karakter hingga mencapai akumulasi numerik `0x01006873` (merepresentasikan karakter ASCII `'s'`, `'h'`, `'\0'`). Penentu `%18$n` menuliskan nilai ini ke alamat heap yang ditunjuk oleh `Portfolio *p` (argumen ke-18).

3. **Pemicuan Eksekusi Perintah Shell (Trigger Execution):**
   - Setelah `buy_stonks()` selesai, alur program kembali ke `main()` dan memanggil `free_portfolio(p)`.
   - Fungsi `free_portfolio(p)` memanggil `free(p->head)` lalu `free(p)`.
   - Karena entri `free@got` telah dibajak menjadi `system@plt` dan struktur `p` diawali dengan string `"sh\0"`, panggilan sistem mengeksekusi `system("sh")`.
   - Perintah shell spawn interaktif didapatkan, memungkinkan eksekusi `cat flag.txt` yang menghasilkan bendera:
     `academy{explo1t_m1t1gashuns_7838034c}`.

---

## Rekomendasi Mitigasi & Pengerasan Keamanan (Remediation)
1. **Penerapan Format Specifier Statis:**
   - Jangan pernah meneruskan string variabel masukan pengguna secara langsung sebagai argumen format:
     ```c
     // RENTAN:
     printf(user_buf);
     // AMAN:
     printf("%s", user_buf);
     ```
2. **Kompilasi dengan Full RELRO dan PIE:**
   - Aktifkan perlindungan *Full RELRO* (`-Wl,-z,relro,-z,now`) agar tabel GOT dipetakan sebagai Read-Only setelah pemuatan pustaka dinamis, mencegah pembajakan entri GOT.
   - Aktifkan *PIE* (`-fPIE -pie`) untuk merandomisasi seluruh basis alamat kode dan tabel GOT melalui ASLR sistem operasi.
3. **Pemberlakuan Compiler Warning Guard:**
   - Aktifkan bendera kompilator `-Werror=format-security` dan `-D_FORTIFY_SOURCE=2` untuk menggagalkan kompilasi kode yang memanggil fungsi format string secara tidak aman.

---

## Script Reproduksi
Script solver mandiri tersedia pada berkas `scripts/solve_164_stonk_market.py`.
Jalankan verifikasi dengan perintah:
```bash
python3 scripts/solve_164_stonk_market.py
```
Hasil verifikasi mengembalikan token flag valid:
`academy{explo1t_m1t1gashuns_7838034c}`
