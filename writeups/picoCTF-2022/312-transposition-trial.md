# Writeup: transposition-trial (Challenge ID: 312)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Transposition Cipher
- **Difficulty:** Easy
- **Event:** picoCTF 2022
- **Flag:** `academy{7R4N5P051N6_15_3XP3N51V3_5571D3F8}`

---

## Problem Statement & Scope

File `message312.txt`: `heTfl g as icaaemd{7y4NRP051N5_16_35P3X51N3_V575D318}F`. Tiap blok 3 karakter diputar kanan-1 (karakter terakhir ke depan).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Transposisi blok-tetap mudah dibalik:** operasi `b[-1]+b[:2]` adalah permutasi posisi; inversnya `b[1:]+b[:1]`.
2. **Struktur flag sebagai oracle:** kurung kurawal + `academy` memberi jangkar visual untuk validasi.
3. **Spasi ikut ditransposisi:** jangan strip spasi sebelum decode per-blok.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Baca `message312.txt`.
2. Untuk tiap blok 3 char terapkan invers rotasi.
3. Hasil: `the flag is academy{7R4N5P051N6_15_3XP3N51V3_5571D3F8}`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

---

## Flag & Verifikasi

- **Flag:** `academy{7R4N5P051N6_15_3XP3N51V3_5571D3F8}`
- **Bukti:** `solved_by_user=True` via `GET /api/challenges/312/`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Transposisi tanpa substitusi/key tidak menyembunyikan apapun — kombinasikan dengan cipher modern. Untuk LKS: latih pattern recognition blok + tulis invers generik.
