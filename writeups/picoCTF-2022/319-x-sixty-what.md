# Writeup: x-sixty-what (Challenge ID: 319)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Classic Stack Overflow x64
- **Difficulty:** Easy
- **Event:** picoCTF 2022
- **Flag:** `academy{b1663r_15_b3773r_fb3754c3}`

---

## Problem Statement & Scope

Biner 64-bit dengan `gets()` overflow di `vuln()`: buffer 64 + saved rbp 8 → RIP di offset 72. Fungsi `flag()` membaca `flag.txt`. Lab on-demand (`nc xebec.cylabacademy.net <port>` dari deskripsi instance).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **`gets() tanpa batas:** menulis melewati buffer, menimpa saved rbp + return address. Offset RIP = 64 + 8 = 72.
2. **Stack alignment x64:** masuk di `flag+0` (`push rbp`) membuat stack misaligned → crash di `movaps` dalam printf. Masuk di `flag+1` (`0x40123b`) menjaga alignment 16-byte.
3. **PIE nonaktif:** alamat statis, ret langsung tanpa leak.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Launch: `PUT /api/challenges/319/instance/` → catat `nc host port`.
2. `python3 scripts/solve_319_x_sixty_what.py host port` (payload: `b'A'*72 + p64(0x40123b)`).
3. Flag tercetak. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

---

## Flag & Verifikasi

- **Flag:** `academy{b1663r_15_b3773r_fb3754c3}`
- **Bukti:** `solved_by_user=True` via `GET /api/challenges/319/`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Jangan pernah pakai `gets()`; gunakan `fgets()` + stack canary + ASLR penuh. Untuk LKS: kuasai offset RIP + alignment 16-byte x64 sebagai refleks.
