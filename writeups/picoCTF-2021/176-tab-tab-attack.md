# Writeup: Tab, Tab, Attack (Challenge ID: 176)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Linux Shell Autocompletion & Deep Directory Carving
- **Difficulty:** Easy (diff=1)
- **Author:** syreal
- **Event:** picoCTF 2021
- **Points:** 20
- **Flag:** `academy{l3v3l_up!_t4k3_4_r35t!_9d928112}`

---

## Problem Statement & Scope

Diberikan sebuah arsip ZIP bernama `Addadshashanammu.zip` yang memuat struktur direktori bertingkat sangat dalam (*deeply nested rambling directory structure*) dengan penamaan folder fonetik kuno yang rumit. Deskripsi soal menantang peserta untuk menggunakan fitur navigasi terminal Linux (*tab completion*) guna menjangkau berkas target di ujung hierarki direktori secara efisien dalam hitungan detik.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Efisiensi CLI & Readline Programmable Completion:**
   - Shell Unix (Bash, Zsh) mengimplementasikan pustaka GNU Readline yang menyediakan fitur *Tab Completion*. Ketika path yang tersedia hanya memiliki satu jalur anak unik (*unambiguous prefix*), penekanan tombol `Tab` secara otomatis melengkapi nama direktori secara instan.
   - Skenario ini melatih refleks operator terminal dalam kompetisi LKS Cyber Security untuk melakukan *directory traversal* kilat tanpa mengetik nama panjang secara manual.
2. **Keterbukaan Plaintext pada Berkas Kompilasi (CWE-200 / CWE-312):**
   - Di ujung hierarki direktori terdapat berkas sumber C (`fang-of-haynekhtnamet.c`) dan biner ELF yang dikompilasi (`fang-of-haynekhtnamet`).
   - String flag tidak dienkripsi atau diobfuskasi, melainkan disimpan sebagai string literal pada bagian `.rodata` biner C:
     `printf("*ZAP!* academy{l3v3l_up!_t4k3_4_r35t!_9d928112}\n");`

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Ekstraksi Arsip:**
   Unduh dan ekstrak berkas ZIP yang diberikan:
   ```bash
   unzip Addadshashanammu.zip
   ```
2. **Navigasi Beruntun Menggunakan Tombol TAB:**
   Jalankan perintah navigasi dengan menekan tombol `[TAB]` secara berurutan:
   ```bash
   cd Addad[TAB]/Alm[TAB]/Ash[TAB]/Ass[TAB]/Mael[TAB]/Onn[TAB]/Ula[TAB]
   ```
3. **Eksekusi Biner atau Ekstraksi String:**
   Berikan izin eksekusi lalu jalankan biner:
   ```bash
   chmod +x fang-of-haynekhtnamet
   ./fang-of-haynekhtnamet
   ```
   Atau lakukan pembacaan langsung dari berkas sumber C yang menyertainya:
   ```bash
   cat fang-of-haynekhtnamet.c
   ```
   Output menampilkan flag:
   ```text
   *ZAP!* academy{l3v3l_up!_t4k3_4_r35t!_9d928112}
   ```

---

## Flag & Verifikasi

- **Flag:** `academy{l3v3l_up!_t4k3_4_r35t!_9d928112}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true, "user": 1072359, "challenge": 176}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kecepatan Navigasi Terminal (LKS Speedrun Skills):** Pada modul forensik dan eksplorasi sistem Linux LKS Cyber Security, peserta harus terbiasa dengan autokompleksi Tab dan globbing (`find . -type f -executable`) untuk menemukan berkas artefak mencurigakan di dalam direktori bersarang tanpa tersesat.
- **Penyimpanan Kredensial & Secrets Hygiene:** Hindari menyimpan string rahasia, kunci otentikasi, atau token lisensi dalam bentuk plaintext di dalam kode sumber aplikasi atau biner yang didistribusikan. Gunakan *environment variables*, HSM, atau enkripsi simetris aman.

---

## Solver

Lihat `scripts/solve_176_tab_tab_attack.py` — script Python mandiri untuk menginspeksi hierarki arsip ZIP dalam memori dan mengekstrak token flag secara otomatis.
