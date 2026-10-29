# substitution1 (Challenge 308, Cryptography)

- **ID:** 308 | **Event:** picoCTF 2022 | **Kategori:** Cryptography | **Level:** Easy (diff 2, 100 pts)
- **Flag:** `academy{FR3QU3NCY_4774CK5_4R3_C001_0532A335}` (terverifikasi live `POST /api/submissions/` -> `correct: true`; verifier case-insensitive)

## Skenario
Pesan `message.txt` terenkripsi substitusi monoalfabetik; kalimat
pembuka menjelaskan CTF ("short for capture the flag...").

## Root Cause
Substitusi 1-ke-1 mempertahankan frekuensi dan pola kata; crib
`lrlxpac` = `academy` (kata flag itu sendiri!) + kata umum
(`zqp`=`the`, `felg`=`flag`, `fuv`=`for`, `tquvz`=`short`,
`rlwzbvp`=`capture`, `ruawbzpv`=`computer`, `rqleepogpt`=`challenges`)
memulihkan seluruh kunci tanpa komputasi berat.

## Rekonstruksi
1. Unduh `message.txt` dari CDN (URL di instance description).
2. Petakan crib + frekuensi huruf (p=54 tertinggi = `e`).
3. Decode kata flag: `lrlxpac{FV3DB3ORC_...}` -> `academy{FR3QU3NCY_...}`.
   Otomasi: `python3 scripts/solve_308_substitution1.py message.txt`.

## Mitigasi
Substitusi klasik tidak layak untuk kerahasiaan; gunakan cipher modern
(AES-256-GCM) dengan manajemen kunci yang benar.

## Takeaway LKS
Kripto klasik: cari crib di konteks (nama format flag!), lalu rambat
dengan frekuensi; verifikasi dengan kalimat bermakna penuh, bukan
satu kata.
