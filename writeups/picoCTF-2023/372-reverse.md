# Writeup: Reverse (Challenge ID: 372)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / ELF Binary Analysis
- **Difficulty:** Medium (diff=2)
- **Event:** picoCTF 2023
- **Flag:** `academy{3lf_r3v3r5ing_succe55ful_19e99671}`

---

## Problem Statement & Scope

Tantangan menyediakan file biner executable Linux 64-bit ELF (`ret`). Pengguna lupa password pembuka file tersebut dan diminta menganalisis alur verifikasi atau membedah struktur internal program untuk memperoleh password / flag yang valid.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Biner ELF & Unstripped Symbols (NIST SP 800-115 Static Analysis):** File biner `ret` dikompilasi tanpa proses stripping simbol dan tidak diobfuskasi. Hal ini memungkinkan analis menelaah struktur fungsi `main`, tabel string `.rodata`, dan instruksi perakitan mesin (*assembly instructions*) secara transparan.
2. **Hardcoded Secret Literal & Format String Storage:** Program membandingkan input pengguna dengan password tertentu, dan saat cocok, mencetak string flag yang telah dikonstruksi secara statis. String rahasia tersebut disimpan baik di section `.rodata` maupun dikonstruksi langsung pada stack frame melalui rangkaian instruksi 64-bit `movabs` ke memori stack `[rbp-0x90]` s/d `[rbp-0x68]`.
3. **Pembedahan Assembly:**
   - `0x7b796d6564616361` -> `academy{`
   - `0x337633725f666c33` -> `3lf_r3v3`
   - `0x75735f676e693572` -> `r5ing_su`
   - `0x6c75663535656363` -> `cce55ful`
   - `0x373639396539315f` -> `_19e9967`
   - `0x7d31`             -> `1}`

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh file biner `ret` dari CDN CyLab Academy (`challenge-files.cylabacademy.net/library/...`).
2. Analisis tipe biner dan perizinan:
   ```bash
   file ret
   # ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked
   chmod +x ret
   ```
3. Lakukan inspeksi string statis untuk mencari pola flag:
   ```bash
   strings ret | grep -E "(academy|picoCTF)\{"
   ```
   Ditemukan format string penyerahan flag: `Password correct, please see flag: academy{3lf_r3v3r5ing_succe55ful_19e99671}`.
4. Lakukan verifikasi logika perakitan via `objdump`:
   ```bash
   objdump -d -M intel ret | grep -A 35 "<main>:"
   ```
5. Otomasi ekstraksi dan pengujian via skrip `scripts/solve_372_reverse.py`.
6. Verifikasi token via REST API: `POST /api/submissions/` dengan payload `{"challenge": 372, "flag": "academy{3lf_r3v3r5ing_succe55ful_19e99671}"}` menghasilkan status HTTP 201 `correct: true`.

---

## Flag & Verifikasi

- **Flag:** `academy{3lf_r3v3r5ing_succe55ful_19e99671}`
- **Bukti:** Submisi REST API `/api/submissions/` mengembalikan `{"correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS:** Penguasaan disassembly ELF x86-64, pembacaan stack frame pointer, rekonsiliasi data endianness (Little-Endian QWORD packing), dan inspeksi section `.rodata`.
- **Mitigasi Defensif:** Jangan menyematkan kredensial atau secret di dalam biner sisi klien (client-side binary). Lakukan *binary stripping* (`strip -s`), proteksi enkripsi runtime (packer), atau gunakan otentikasi berbasis server yang aman.
