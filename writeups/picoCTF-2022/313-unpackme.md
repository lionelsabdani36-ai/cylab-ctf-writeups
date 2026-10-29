# Writeup: unpackme (Challenge ID: 313)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / UPX Packed Binary
- **Difficulty:** Easy
- **Event:** picoCTF 2022
- **Flag:** `academy{up><_m3_f7w_a6924bf9}`

---

## Problem Statement & Scope

File `unpackme-upx` (ELF 64-bit, 380KB, terkompresi UPX). `strings` langsung tidak memuat flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **UPX hanya kompresi, bukan enkripsi:** header `UPX!` + section `UPX0/UPX1` menandai stub unpacker. `upx -d` memulihkan biner asli.
2. **Fallback tanpa upx:** stub UPX bisa dilewati dengan dump memori saat runtime atau analisis `strings` pada image ter-unpack.
3. **Flag inline di .rodata:** setelah unpack, `academy{...}` terbaca via `strings`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. `upx -d unpackme-upx -o unpacked` (atau analisis manual bila upx tidak tersedia).
2. `strings unpacked | grep academy`.
3. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

---

## Flag & Verifikasi

- **Flag:** `academy{up><_m3_f7w_a6924bf9}`
- **Bukti:** `solved_by_user=True` via `GET /api/challenges/313/`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Packer bukan proteksi — untuk anti-tamper gunakan obfuscation + attestation. Untuk LKS: kenali signature UPX (`UPX!`, section anomali) + workflow unpack standar.
