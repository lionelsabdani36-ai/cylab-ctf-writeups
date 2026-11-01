# Writeup: FactCheck (Challenge ID: 416)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / C++ String Construction & Control Flow Analysis
- **Difficulty:** Medium
- **Author:** Junias Bonou
- **Event:** picoCTF 2024
- **Points:** 200
- **Flag:** `academy{wELF_d0N3_mate_9480e1e2}`

---

## Problem Statement & Scope
Diberikan sebuah berkas biner ELF 64-bit Linux (`bin`) yang tidak di-*strip* (*not stripped*). Program bertugas merangkai suatu informasi penting di memori selama masa eksekusi, tetapi tidak mencetaknya secara langsung ke *standard output*. Analis diminta merekayasa balik alur logika eksekusi biner guna merekonstruksi string flag lengkap.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Dynamic String Construction in C++ (`std::string`):** Biner dibangun dengan pustaka standar C++ (`libstdc++`) menggunakan kelas `std::__cxx11::basic_string`. Seluruh konstanta karakter disimpan di bagian `.rodata` dan diinstansiasi menjadi objek string lokal pada frame stack `main`.
2. **Deterministic Control-Flow Invariants:** Rutin `main` melakukan serangkaian evaluasi predikat bersyarat statis menggunakan nilai konstan ASCII:
   - Nilai variabel `[rbp-0x200]` adalah `"5"` ($0x35$). Instruksi `cmp al, 0x41; setle al` mengevaluasi apakah $'5' \le 'A'$ ($0x35 \le 0x41$). Kondisi ini selalu bernilai **TRUE**, sehingga string `"9"` (`[rbp-0xc0]`) digabungkan ke buffer flag.
   - Nilai variabel `[rbp-0xa0]` adalah `"6"` ($0x36$). Instruksi `cmp al, 0x41; setne al` mengevaluasi $'6' \ne 'A'$ ($0x36 \ne 0x41$). Kondisi ini selalu bernilai **TRUE**, sehingga string `"4"` (`[rbp-0x60]`) digabungkan.
   - Nilai variabel `[rbp-0x1c0]` adalah `"3"` ($0x33$) dan `[rbp-0x140]` adalah `"e"` ($0x65$). Instruksi `sub edx, eax; cmp edx, 0x03` mengevaluasi $'3' - 'e' = -50 == 3$. Kondisi ini bernilai **FALSE**, sehingga penggabungan `"3"` dilewati (*skipped*).
   - Penggabungan tanpa syarat (*unconditional append*): `"8"` (`[rbp-0x1e0]`) dan `"0"` (`[rbp-0x180]`).
   - Nilai variabel `[rbp-0x160]` adalah `"a"` ($0x61$). Instruksi `cmp al, 0x47; sete al` mengevaluasi $'a' == 'G'$ ($0x61 == 0x47$). Kondisi ini bernilai **FALSE**, sehingga penggabungan `"a"` dilewati.
   - Penggabungan tanpa syarat akhir: `"e"`, `"1"`, `"e"`, `"2"`, dan karakter penutup `}` ($0x7d$).
3. **Analisis Statis Murni (Pure Static Disassembly):** Karena seluruh predikat percabangan bergantung secara eksklusif pada konstanta hardcoded di `.rodata` tanpa bergantung pada input eksternal pengguna, flag dapat ditentukan secara mutlak melalui disasembli tanpa memerlukan emulasi dinamis atau eksekusi runtime.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis simbol dan struktur seksi biner:
   ```bash
   readelf -p .rodata bin
   # [ 8]  academy{wELF_d0N3_mate_
   # [20]  e
   # [22]  5
   # [24]  8
   # [26]  3
   # [28]  0
   # [2a]  a
   # [2c]  2
   # [2e]  d
   # [30]  b
   # [32]  9
   # [34]  6
   # [36]  1
   # [38]  4
   ```
2. Lakukan disasembli fungsi `main` menggunakan `objdump -M intel -d bin`.
3. Petakan alur operasi string:
   - Basis: `academy{wELF_d0N3_mate_`
   - Syarat 1: `'5' <= 'A'` $\rightarrow$ **True** $\rightarrow$ `+ "9"`
   - Syarat 2: `'6' != 'A'` $\rightarrow$ **True** $\rightarrow$ `+ "4"`
   - Syarat 3: `'3' - 'e' == 3` $\rightarrow$ **False** $\rightarrow$ skip `"3"`
   - Append: `+ "8"`
   - Append: `+ "0"`
   - Syarat 4: `'a' == 'G'` $\rightarrow$ **False** $\rightarrow$ skip `"a"`
   - Append: `+ "e"`
   - Append: `+ "1"`
   - Append: `+ "e"`
   - Append: `+ "2"`
   - Append: `+ "}"`
4. Hasil akhir rekonstruksi:
   $$\text{academy\{wELF\_d0N3\_mate\_9480e1e2\}}$$

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{wELF_d0N3_mate_9480e1e2}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 416, "flag": "academy{wELF_d0N3_mate_9480e1e2}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Opaque Predicates & Obfuskasi Logika Alur Kontrol:** Tantangan ini mendemonstrasikan konsep *opaque predicates* sederhana di mana kode biner menyisipkan percabangan yang secara matematis selalu deterministik (True atau False) untuk memperlambat analis. Pada modul *Binary Analysis / Malware Analysis* LKS Cyber Security, analis harus mampu mengenali pola komparasi register konstan untuk memotong jalur dead-code.
- **Pembersihan String dan Simbol Biner (Binary Stripping):** Jangan mendistribusikan biner kompilasi tanpa melakukan *stripping* (`strip -s`) atau kompresi pengaburan string. Penggunaan konstanta string mentah di `.rodata` mempermudah rekayasa balik dalam hitungan detik.
