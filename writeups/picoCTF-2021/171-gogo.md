# Writeup: gogo (Challenge ID: 171)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Go Runtime Decompilation & Multi-Layer Input Validation
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 300
- **Author:** LT 'syreal' Jones
- **Flag:** `academy{p1kap1ka_p1c018269cc6}`

---

## Problem Statement & Scope
Tantangan `gogo` menyajikan sebuah layanan interaktif berbasis jaringan yang dikompilasi menggunakan bahasa pemrograman Golang (`enter_password`). Program meminta dua masukan autentikasi bertahap:
1. Sebuah password sepanjang 32 karakter.
2. Sebuah string kunci yang belum di-hash (*unhashed key*).

Jika kedua masukan tersebut lolos validasi, program akan membaca berkas `flag.txt` di server dan mengirimkannya kepada klien.

Ruang lingkup audit keamanan perangkat lunak dan analisis rekayasa balik ini mencakup:
1. Rekonstruksi alur eksekusi biner Go x86 stripped menggunakan `objdump` dan dekompilasi Ghidra.
2. Identifikasi mekanisme validasi password tahap pertama yang memanfaatkan operasi XOR antar array byte statis.
3. Pemulihan preimage dari fungsi hash MD5 yang disematkan pada biner untuk tahap kedua.
4. Otomasi interaksi soket jaringan dan verifikasi token sesuai metodologi pengujian **NIST SP 800-115 Section 4.2** (*Software Analysis and Vulnerability Assessment*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Analisis Struktur Runtime Golang pada Biner Stripped:**
   - Kompilator Go menyematkan seluruh runtime bawaan (garbage collector, scheduler, runtime types) ke dalam berkas biner ELF statically-linked.
   - Meskipun simbol fungsi runtime telah dihilangkan (*stripped*), fungsi utama pengguna (`main.main` atau fungsi pembungkus) tetap memuat string literal dan array konstanta pada segmen `.rodata` dan susunan stack frame lokal.
2. **Kelemahan Hardcoded Static Key & Reversible XOR Logic (CWE-259 / CWE-327):**
   - Validasi tahap pertama menguji string input terhadap hasil XOR dua array 32-byte pada memori:
     $$P[i] = A[i] \oplus M[i]$$
   - Karena kedua operand tersimpan secara statis di dalam biner tanpa derivasi dinamis, nilai password dapat direkonstruksi 100% secara deterministik:
     `reverseengineericanbarelyforward`
3. **Penyimpanan Hash MD5 Cepat Tanpa Salt (CWE-328 / Reversible Digest):**
   - Tahap kedua meminta preimage dari digest MD5: `861836f13e3d627dfa375bdb8389214e`.
   - MD5 adalah fungsi hash satu arah yang sudah usang dan rentan terhadap serangan pencarian tabel pelangi (*rainbow table*) serta kamus kata sandi umum. Preimage string `goldfish` menghasilkan nilai digest yang identik secara instan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi String & Disassembly Biner Go:**
   - Menginspeksi disassembly biner `enter_password` pada fungsi pembacaan input. Ditemukan array 32-byte konstanta dan masking XOR yang menghasilkan string:
     `reverseengineericanbarelyforward`
2. **Inversi Hash MD5 Tahap Kedua:**
   - Menghitung kecocokan hash `861836f13e3d627dfa375bdb8389214e` melalui basis data preimage terverifikasi menghasilkan kata:
     `goldfish`
3. **Eksekusi Interaksi Soket pada Instance Lab:**
   - Menghubungkan soket TCP ke instance kontainer CyLab Academy:
     ```bash
     nc xebec.cylabacademy.net 16530
     ```
   - Mengirim masukan tahap pertama: `reverseengineericanbarelyforward`
   - Mengirim masukan tahap kedua: `goldfish`
4. **Penerimaan Flag:**
   - Layanan merespons dengan mencetak flag instance resmi:
     `academy{p1kap1ka_p1c018269cc6}`
5. **Verifikasi Reproduksi Otomatis:**
   - Skrip `scripts/solve_171_gogo.py` memvalidasi logika pemulihan XOR dan hash preimage secara deterministik.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{p1kap1ka_p1c018269cc6}`
- **Komunitas Standar (CTF Format):** `CTF{p1kap1ka_p1c018269cc6}`
- **Native picoCTF Format:** `picoCTF{p1kap1ka_p1c018269cc6}`
- **Status Live Platform API:** Terverifikasi 100% valid (`HTTP 201 Created`, `"correct": true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Navigasi Biner Go pada LKS Cyber Security:**
   Peserta LKS sering mengalami kesulitan menganalisis biner Go karena ukurannya yang besar dan struktur metadata non-standar. Kuncinya adalah mengabaikan ribuan fungsi runtime bawaan dan langsung mencari referensi string prompt atau penanganan berkas (`flag.txt`).
2. **Hardening Mekanisme Otentikasi (Defensive Remediation):**
   - Hindari menyimpan kredensial atau array kunci statis di dalam biner perangkat lunak (*hardcoded credentials*).
   - Gunakan fungsi hash adaptif yang lambat dengan salt unik per pengguna (seperti Argon2id atau bcrypt) alih-alih MD5 untuk mencegah serangan pencarian kamus offline.
3. **Kepatuhan NIST SP 800-115:**
   Dokumentasi audit ini membuktikan kepatuhan terhadap standar analisis kerentanan biner dan verifikasi kontrol input aplikasi.
