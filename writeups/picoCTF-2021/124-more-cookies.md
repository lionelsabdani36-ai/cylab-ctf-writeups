# Writeup: More Cookies (Challenge ID: 124)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / CBC Bit-Flipping
- **Difficulty:** Medium
- **Author:** madStacks
- **Event:** picoCTF 2021
- **Points:** 200
- **Flag:** `academy{cO0ki3s_yum_df66be3e}`

---

## Problem Statement & Scope
Halaman "More Cookies" hanya menampilkan form pencarian untuk admin. Server memberi cookie `auth_name` yang terenkripsi; tugas: menjadi admin tanpa mengetahui kunci.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Struktur cookie:** `auth_name = base64(base64(ciphertext))` dengan ciphertext 96 byte AES-CBC (didapat dari dua kali `base64.b64decode`).
2. **CBC malleable:** pada AES-CBC, flip bit ke-i pada blok ciphertext N membalik bit yang sama pada blok plaintext N+1 (dengan mengacak blok N — dapat diterima karena blok yang relevan tetap valid).
3. **Bit-flip brute force:** plaintext mengandung `is_admin=0`; membalik 1 bit pada posisi yang tepat mengubahnya menjadi `is_admin=1`. Karena posisi tak diketahui, coba semua 768 posisi (96 byte × 8 bit) hingga server menampilkan flag, bukan redirect.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Provision instance, ambil cookie via `curl -c` (double-base64, 96 byte setelah 2× decode).
2. Untuk tiap posisi bit (byte 0–95, bit 0–7): XOR 1 bit, re-encode double-base64, GET halaman dengan cookie hasil forge.
3. Server menampilkan `<b>Flag</b>: <code>academy{cO0ki3s_yum_df66be3e}</code>` pada posisi yang tepat.
4. Submit flag via API → `correct: true`.

---

## Flag & Verifikasi
- **Flag:** `academy{cO0ki3s_yum_df66be3e}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Jangan memakai CBC tanpa MAC** untuk data terotentikasi; gunakan mode AEAD (AES-GCM) atau tambahkan HMAC.
- **Homomorphic hint:** deskripsi yang menyebut enkripsi homomorfik/CBC adalah sinyal klasik serangan bit-flipping.
- Skrip brute-force 768 posisi adalah template LKS standar untuk oracle CBC.

---

## Solver
Lihat `scripts/solve_124_more_cookies.py` — double-decode cookie, brute-force 768 flip, dan mengembalikan flag.
