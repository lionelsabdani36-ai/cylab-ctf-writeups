# Writeup: Investigative Reversing 4 (Challenge ID: 54)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Reverse Engineering & Multi-File Steganography
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 400
- **Author:** Danny
- **Flag:** `academy{N1c3_R3ver51ng_5k1115_000000000004e619b22}`

---

## Problem Statement & Scope
Tantangan `Investigative Reversing 4` memberikan skenario forensik digital multi-artefak di mana pelaku ancaman menyembunyikan data rahasia ke dalam beberapa berkas gambar secara terfragmentasi. Analis diberikan berkas biner ELF 64-bit `mystery` serta kumpulan 5 berkas gambar bitmap: `Item01.bmp`, `Item02.bmp`, `Item03.bmp`, `Item04.bmp`, dan `Item05.bmp`.

Ruang lingkup pengujian meliputi dekompilasi statis algoritma biner penanganan multi-berkas x86_64, identifikasi offset penyisipan bit pada berkas citra BMP, analisis fragmentasi payload antar-berkas (*cross-file payload sharding*), pengurutan rekonstruksi berkas secara terbalik (*reverse chronological file ordering*), dan kepatuhan standar pembuktian digital forensik **NIST SP 800-115 Section 4.3**.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Fragmentasi Data Multi-Berkas & Pengurutan Terbalik (Cross-File Sharding & Reverse Sequence / CWE-312):**
   - Biner `mystery` membaca 50 karakter bendera dari `flag.txt` dan membaginya menjadi 5 pecahan (*chunks*), masing-masing sepanjang 10 karakter (80 bit).
   - Pengurutan penulisan berkas pada biner dirancang secara terbalik terhadap konvensi penamaan leksikografis berkas:
     - Berkas indeks ke-5 (`Item05.bmp`) memuat pecahan karakter 0..9 (`academy{N1`).
     - Berkas indeks ke-4 (`Item04.bmp`) memuat pecahan karakter 10..19 (`c3_R3ver51`).
     - Berkas indeks ke-3 (`Item03.bmp`) memuat pecahan karakter 20..29 (`ng_5k1115_`).
     - Berkas indeks ke-2 (`Item02.bmp`) memuat pecahan karakter 30..39 (`0000000000`).
     - Berkas indeks ke-1 (`Item01.bmp`) memuat pecahan karakter 40..49 (`04e619b22}`).
   - Apabila seorang analis membaca berkas dalam urutan normal `Item01` ke `Item05`, fragmen string yang didapat terbalik secara blok, memperlambat proses identifikasi awal.

2. **Kelemahan Penyamaran Berkas Tanpa Kriptografi Otentik (CWE-327):**
   - Masing-masing pecahan 10 karakter disuntikkan ke dalam LSB kanal warna piksel BMP mulai dari offset 2048 (0x800).
   - Ketiadaan enkripsi simetris (seperti AES) atau penandatanganan integritas kriptografis membuat seluruh struktur data dapat direkonstruksi secara penuh segera setelah urutan pembacaan berkas dibalikkan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Dekompilasi Biner ELF (Ghidra / IDA Pro):**
   - Melakukan inspeksi terhadap perulangan utama biner `mystery`:
     ```c
     char *filenames[] = {"Item01.bmp", "Item02.bmp", "Item03.bmp", "Item04.bmp", "Item05.bmp"};
     FILE *f_flag = fopen("flag.txt", "r");
     
     // Loop iterasi mundur dari index 4 ke 0
     for (int f = 4; f >= 0; f--) {
         FILE *bmp_in = fopen(filenames[f], "r");
         // Baca dan embedding 10 karakter ke dalam file BMP terkait
         for (int i = 0; i < 10; i++) {
             char c = fgetc(f_flag);
             embed_char_lsb(bmp_in, c);
         }
     }
     ```
   - Terlihat jelas bahwa `f` berjalan dari 4 (`Item05.bmp`) menurun ke 0 (`Item01.bmp`).

2. **Ekstraksi LSB dari Setiap Berkas BMP:**
   - Membaca 80 byte data piksel mulai dari offset 2048 (0x800) pada setiap berkas BMP.
   - Merekonstruksi 10 karakter per berkas:
     $$c_j = \sum_{k=0}^{7} (\text{byte}_{j \times 8 + k} \ \& \ 1) \ll k$$
   - Hasil ekstraksi per berkas:
     - `Item05.bmp`: `academy{N1`
     - `Item04.bmp`: `c3_R3ver51`
     - `Item03.bmp`: `ng_5k1115_`
     - `Item02.bmp`: `0000000000`
     - `Item01.bmp`: `04e619b22}`

3. **Penyusunan Ulang Blok (Block Reassembly):**
   - Menggabungkan pecahan dari urutan berkas 5 ke 1:
     $$\text{Flag} = \text{Block}(5) + \text{Block}(4) + \text{Block}(3) + \text{Block}(2) + \text{Block}(1)$$
   - Menghasilkan token utuh:
     `academy{N1c3_R3ver51ng_5k1115_000000000004e619b22}`

4. **Validasi Skrip Otomasi Mandiri:**
   - Mengeksekusi skrip reproduktif mandiri:
     ```bash
     python3 scripts/solve_54_investigative_reversing_4.py
     ```
   - Skrip memverifikasi pembacaan multi-berkas dan penyusunan ulang urutan blok dengan benar.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{N1c3_R3ver51ng_5k1115_000000000004e619b22}`
- **Komunitas Standar (CTF Format):** `CTF{N1c3_R3ver51ng_5k1115_000000000004e619b22}`
- **Status Verifikasi:** Terverifikasi 100% pada pembalikan urutan pembacaan berkas multi-artefak LSB.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Rantai Bukti Multi-Artefak:**
   Pada lomba LKS Cyber Security bidang Digital Forensics, artefak insiden seringkali tidak terkonsentrasi pada satu berkas tunggal, melainkan dipecah di beberapa artefak terpisah. Analis harus teliti memeriksa keterkaitan *metadata timestamps* dan alur kontrol pembuat berkas.
2. **Pertahanan Mendalam Terhadap Ekfiltrasi Data:**
   Sistem pemantauan lalu lintas data (DLP dan Network Forensics) wajib melakukan inspeksi berbasis entropi dan korelasi transmisi serentak (*burst transmissions of media files*) untuk mendeteksi upaya eksfiltrasi terfragmentasi.
3. **Kepatuhan NIST SP 800-115:**
   Menyediakan script reproduksi mandiri dan pemetaan alur algoritma secara terperinci memastikan temuan forensik dapat diaudit secara independen tanpa ambigu.
