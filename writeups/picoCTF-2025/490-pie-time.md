# Writeup: PIE TIME (Challenge ID: 490)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / PIE Offset & Function Pointer Subversion
- **Difficulty:** Medium
- **Event:** picoCTF 2025
- **Points:** 75
- **Flag:** `academy{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}`

---

## Problem Statement & Scope
Disediakan berkas ELF 64-bit yang dikompilasi dengan proteksi Position Independent Executable (PIE). Peserta diminta melompat ke fungsi `win()` untuk mencetak flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Information Leak:** Biner membocorkan alamat memori fungsi `main()` saat runtime.
2. **Relative Offset Invariance:** Meskipun basis alamat memori diacak oleh ASLR/PIE, offset relatif antara fungsi `win()` dan `main()` tetap konstan pada biner yang sama.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Lakukan disassembly biner menggunakan `objdump` atau GDB untuk menghitung offset:
   $$	ext{offset} = 	ext{addr}(	ext{win}) - 	ext{addr}(	ext{main}) = -0xa2$$
2. Tangkap alamat bocoran `main()` dari output biner.
3. Hitung alamat target: $	ext{win} = 	ext{main} - 0xa2$.
4. Kirimkan alamat target ke input program untuk mengeksekusi `win()`.

---

## Flag & Verifikasi
- **Flag:** `academy{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **CFI & Leak Elimination:** Hilangkan rutin diagnostik yang mencetak alamat pointer dan aktifkan Control Flow Integrity (CFI).
