# Writeup: Wave a flag (Challenge ID: 170)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Linux CLI Parameter Invocation & Binary String Carving
- **Difficulty:** Easy (diff=1)
- **Author:** syreal
- **Event:** picoCTF 2021
- **Points:** 10
- **Flag:** `academy{b1scu1ts_4nd_gr4vy_57d8c79}`

---

## Problem Statement & Scope

Diberikan sebuah berkas biner ELF Linux 64-bit bernama `warm`. Deskripsi soal menanyakan kemampuan peserta dalam memanggil opsi bantuan (*help flags*): *"Can you invoke help flags for a tool or binary? This program has extraordinarily helpful information..."*.

Tantangan ini menguji pemahaman dasar navigasi terminal Linux, pemberian atribut izin eksekusi (`chmod +x`), serta penguraian argumen baris perintah (*CLI flag conventions* seperti `-h` dan `--help`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Konvensi Antarmuka Baris Perintah (POSIX CLI Standards):**
   - Utilitas Linux standar mengimplementasikan parser argumen baris perintah (`getopt` / `getopt_long`) yang merespons argumen `-h` atau `--help` dengan mencetak petunjuk penggunaan.
   - Sering kali dalam tantangan CTF dan modul asesmen penetrasi (NIST SP 800-115), biner pengujian atau utilitas diagnostik internal membocorkan kredensial atau parameter sensitif di dalam pesan bantuan.
2. **Keterbukaan String Statis (CWE-200 / CWE-312):**
   - Program `warm` menyimpan pesan bantuan dan string flag dalam bentuk teks biasa di segmen data hanya-baca (`.rodata` ELF section).
   - Tanpa teknik proteksi atau enkripsi, string tersebut dapat diekstraksi baik melalui eksekusi dinamis dengan argumen `-h` maupun analisis statis menggunakan utilitas `strings`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pemberian Izin Eksekusi & Uji Coba Awal:**
   Unduh biner, berikan atribut eksekusi, lalu jalankan biner tanpa argumen:
   ```bash
   chmod +x warm
   ./warm
   ```
   Program menampilkan pesan panduan:
   ```text
   Hello user! Pass me a -h to learn what I can do!
   ```
2. **Pemanggilan Opsi Bantuan (`-h`):**
   Jalankan program dengan argumen `-h`:
   ```bash
   ./warm -h
   ```
   Program merespons dengan mencetak flag:
   ```text
   Oh, help? I actually don't do much, but I do have this flag here: academy{b1scu1ts_4nd_gr4vy_57d8c79}
   ```
3. **Alternatif Analisis Statis (Offline String Carving):**
   Flag juga dapat langsung ditemukan tanpa mengeksekusi biner menggunakan utilitas `strings`:
   ```bash
   strings warm | grep "academy{"
   ```

---

## Flag & Verifikasi

- **Flag:** `academy{b1scu1ts_4nd_gr4vy_57d8c79}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true, "user": 1072359, "challenge": 170}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Eksplorasi Parameter Program (LKS General Skills):** Peserta kompetisi LKS Cyber Security harus selalu memeriksa opsi `-h`, `--help`, `-v`, atau manual page (`man`) setiap kali berinteraksi dengan utilitas baru atau biner yang belum dikenal.
- **Hardening Biner & Sanitasi Pesan Bantuan:** Dalam pengembangan perangkat lunak produksi yang aman (NIST SP 800-64), jangan menyematkan kredensial default, kunci rahasia pengembang, atau URL internal ke dalam pesan panduan bantuan atau variabel teks statis program.

---

## Solver

Lihat `scripts/solve_170_wave_a_flag.py` — script otomasi mandiri untuk mengeksekusi biner dengan parameter `-h` atau melakukan carving string secara statis jika dijalankan di arsitektur non-x86.
