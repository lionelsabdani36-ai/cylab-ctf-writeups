# Writeup: substitution2 (Challenge ID: 309)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Monoalphabetic Substitution
- **Difficulty:** Easy
- **Event:** picoCTF 2022
- **Flag:** `academy{N6R4M_4N41Y515_15_73D10U5_FD56C357}`

---

## Problem Statement & Scope

File `message309.txt` (1288 karakter, tanpa spasi/tanda baca). Cipher substitusi monoalfabetik a-z; digit/underscore lolos apa adanya. Flag ada di plaintext dengan format tantangan lama.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Substitusi 1-ke-1 mempertahankan statistik bahasa:** distribusi frekuensi huruf cipher adalah permutasi distribusi Inggris. Quadgram log-probability dari teks referensi (War and Peace) memberi fungsi skor untuk hill-climbing.
2. **Simulated annealing:** tukar dua huruf acak, terima sesuai suhu. Crib `theflagis` memvalidasi hasil.
3. **Case folding:** cipher lowercase semua; flag asli uppercase sebagian — cocokkan case-insensitive, submit versi yang diterima verifier.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh `message309.txt`.
2. Jalankan `python3 scripts/solve_309_substitution2.py message309.txt`.
3. Solver hill-climb → plaintext prosa kompetisi keamanan SMA, ekor: `...theflagis academy{...}`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

---

## Flag & Verifikasi

- **Flag:** `academy{N6R4M_4N41Y515_15_73D10U5_FD56C357}`
- **Bukti:** `solved_by_user=True` via `GET /api/challenges/309/`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Substitusi klasik tidak aman untuk data apapun — gunakan cipher modern (AES-GCM). Untuk LKS Forensics/Crypto: kuasai analisis frekuensi + n-gram scoring sebagai baseline sebelum brute force.
