# Writeup: fermat-strings (Challenge ID: 215)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Split-Buffer Format String & GOT Hijacking (CWE-134 / CWE-120)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 250
- **Author:** redpwn
- **Flag:** `academy{f3rm4t_pwn1ng_s1nc3_th3_17th_c3ntury}`

---

## Problem Statement & Scope
Tantangan `fermat-strings` menyajikan program biner ELF 64-bit (`x86_64-64-little`) bertemakan Fermat's Last Theorem yang menerima dua string masukan pengguna (`A` dan `B`) masing-masing hingga 256 byte (`SIZE 0x100`). Program dikompilasi dengan proteksi Partial RELRO, No Stack Canary, NX enabled, dan No PIE (`0x400000`).

Setelah membaca masukan, program melakukan validasi numerik `a = atoi(A)` dan `b = atoi(B)`; jika salah satu bernilai nol, eksekusi langsung dihentikan. Jika lolos, program menggabungkan string masukan ke dalam buffer lokal menggunakan `snprintf(buffer, SIZE, "Calculating for A: %s and B: %s\n", A, B)` dan mencetaknya secara langsung menggunakan `printf(buffer)` tanpa format specifier statis. Peserta ditugaskan untuk membobol validasi `atoi`, mengeksploitasi format string 64-bit untuk membocorkan alamat memori LibC, menimpa entri Global Offset Table (GOT) untuk mengulang aliran eksekusi, dan akhirnya membajak fungsi `atoi@GOT` menjadi `system()` untuk memunculkan shell interaktif dan membaca flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Uncontrolled Format String (CWE-134):**
   Pemanggilan `printf(buffer)` di mana isi `buffer` sepenuhnya dikendalikan oleh pengguna merupakan kerentanan kritis. Penyerang dapat menyisipkan penentu format (`%p`, `%s`, `%x`) untuk membaca nilai sembarang dari register dan stack, serta `%n` / `%hn` / `%hhn` untuk menulis jumlah karakter yang telah dicetak ke alamat pointer tertentu.
2. **Kelemahan Parser Semantik `atoi()` (CWE-20):**
   Fungsi `atoi` membaca karakter awal hingga menemukan karakter non-angka pertama. Karakter setelah digit angka diabaikan. Penyerang dapat menyamarkan payload eksploitasi dengan mengawali string menggunakan bilangan valid (misalnya `111_%p`), sehingga `atoi("111_...")` mengembalikan nilai integer `111` ($\ne 0$), melewati pemeriksaan keamanan aplikasi.
3. **Penyelundupan Null Byte melalui Pemisahan Buffer Ganda (Split-Buffer Smuggling):**
   Pada arsitektur 64-bit x86_64, alamat memori pengguna umumnya memuat byte null (`0x00`). Jika alamat target diletakkan langsung di dalam string format `A`, fungsi `snprintf` akan memotong string pada byte null pertama, merusak sisa payload format specifier. 
   Namun, program menyimpan buffer masukan asli `A` dan `B` pada stack frame lokal sebelum memanggil `snprintf`. Dengan menempatkan format specifier (`%43$s`, `%44$s`, `%45$lln`) pada string `A`, dan menempatkan daftar alamat target 64-bit pada string `B`, string `A` tetap bebas dari byte null saat diproses oleh `snprintf`. Saat `printf(buffer)` dieksekusi, specifier berbasis argumen posisi (`%43$`) melompat melintasi frame stack menuju lokasi buffer asli `B` yang memuat alamat mentah tanpa terpotong.
4. **Relocation Table Hijacking (GOT Overwrite, Partial RELRO):**
   Karena biner dikompilasi dengan Partial RELRO dan No PIE, seksi `.got.plt` bersifat writable (`RW`) pada alamat statis:
   - `puts@GOT` = `0x601018`
   - `atoi@GOT` = `0x601058`
   Menimpa `puts@GOT` dengan alamat `main` (`0x400837`) memastikan bahwa ketika fungsi `puts` dipanggil di akhir loop, program melompat kembali ke `main()` untuk tahap eksploitasi kedua tanpa terminasi proses (menjaga alamat dasar LibC tetap konstan).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pemetaan Offset Posisi Stack (Stack Alignment & Offset Calculation):**
   Melalui analisis debugger GDB/GEF, dipetakan bahwa argumen `B` pada stack berada tepat pada posisi offset `%43$` terhadap pointer format string `printf`.
2. **Tahap 1: Pembocoran Alamat LibC & Looping `puts@GOT`:**
   Penyerang mengirimkan payload ganda:
   - Buffer `A`: `111_%43$s.%44$s.%2066c%45$lln%9c%46$hhn`
   - Buffer `B`: Alamat `puts@GOT` (`0x601018`), `atoi@GOT` (`0x601058`), dan target byte overwrite `puts@GOT` menjadi `0x400837` (`main`).
   Hasilnya:
   - Program mencetak alamat runtime `puts` (`0x7fc4a92d55a0`) dan `atoi` (`0x7fc4a9295730`).
   - Alamat dasar LibC dihitung: `libc_base = 0x7fc4a924e000`.
   - Fungsi `system` dihitung pada alamat: `0x7fc4a929d4e0`.
   - `puts@GOT` dialihkan ke `main()`, sehingga program kembali meminta input `A:` dan `B:`.
3. **Tahap 2: Pembajakan `atoi@GOT` menjadi `system()`:**
   Pada putaran kedua, penyerang mengirimkan payload penulisan byte berganda (%hhn) untuk menulis alamat 64-bit `system` ke dalam pointer `atoi@GOT` (`0x601058`).
4. **Tahap 3: Eksekusi Perintah Arbitrer & Spawn Shell:**
   Pada putaran ketiga, penyerang cukup mengirimkan:
   - Buffer `A`: `/bin/sh`
   - Buffer `B`: string sembarang dummy.
   Program memanggil `atoi(A)`, yang kini melompat ke `system("/bin/sh")`. Shell interaktif terbuka, dan penyerang mengeksekusi `cat flag.txt`.
5. **Normalisasi Token CyLab Academy:**
   Token dinormalisasi sesuai format resmi CyLab: `academy{f3rm4t_pwn1ng_s1nc3_th3_17th_c3ntury}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{f3rm4t_pwn1ng_s1nc3_th3_17th_c3ntury}`
- **Native PicoCTF Flag:** `picoCTF{f3rm4t_pwn1ng_s1nc3_th3_17th_c3ntury}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_215_fermat_strings.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Larangan Penggunaan Format String Dinamis (OWASP ASVS §5.3.4 & CWE-134 Remediation):**
   Fungsi keluarga `printf` (`printf`, `sprintf`, `snprintf`, `syslog`) tidak boleh menerima string pengguna sebagai parameter format string. Wajib gunakan format specifier statis:
   ```c
   // Aman: parameter format string bersifat statis dan tak dapat dimanipulasi
   printf("%s", buffer);
   ```
2. **Penerapan Full RELRO & PIE (Binary Hardening Standard):**
   Kompilasi seluruh aplikasi produksi dengan proteksi modern:
   ```bash
   gcc -fPIE -pie -Wl,-z,relro,-z,now -fstack-protector-strong -o secure_app vuln.c
   ```
   Flag `-Wl,-z,now` memaksa dynamic linker menyelesaikan seluruh simbol saat pemuatan dan menandai seksi GOT sebagai *Read-Only* (`RO`), secara permanen menggagalkan serangan penulisan GOT (*GOT overwrite*).
3. **Validasi Input Ketat pada Penguraian Numerik:**
   Jangan mengandalkan fungsi parser longgar seperti `atoi()` yang mengabaikan karakter trailing. Gunakan fungsi validasi ketat seperti `strtol()` dengan verifikasi `endptr` untuk memastikan bahwa seluruh string masukan adalah angka murni:
   ```c
   char *endptr;
   long val = strtol(input, &endptr, 10);
   if (*endptr != '\0' || endptr == input) {
       // Input mengandung karakter non-numerik, tolak secara tegas
       return -1;
   }
   ```
