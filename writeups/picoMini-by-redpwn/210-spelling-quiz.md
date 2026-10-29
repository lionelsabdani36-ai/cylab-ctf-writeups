# spelling-quiz (Challenge 210, Cryptography)

- **ID:** 210 | **Event:** picoMini by redpwn | **Kategori:** Cryptography / Classical Substitution | **Level:** Medium
- **Flag:** `picoCTF{perhaps_the_dog_jumped_over_was_just_tired}` (terverifikasi live `POST /api/submissions/` -> `correct: true`; format `picoCTF{...}` asli, bukan `academy{...}`)

## Skenario
`public.zip` berisi `encrypt.py`, `flag.txt` terenkripsi, dan
`study-guide.txt` (272.543 kata kamus ejaan). `encrypt.py` mengacak
alfabet lalu memetakan tiap huruf (`dictionary[c]`) — substitusi
monoalfabet acak yang sama untuk flag dan study guide.

## Root Cause
Kunci substitusi dipakai ulang untuk korpus plaintext raksasa yang
diketahui strukturnya (kamus bahasa Inggris). Itu crib raksasa:
pola huruf tiap kata (pattern `brcfxba` = `perhaps`) cukup untuk
memulihkan seluruh kunci lewat word-pattern attack.

## Rekonstruksi
1. Unduh `public.zip` dari CDN challenge-files (dengan cookie sesi).
2. Muat wordlist (`words_alpha.txt` 370k kata), kelompokkan per
   `(panjang, pola-huruf)`; petakan tiap kata cipher ke kandidat.
3. Iterasi: kunci kata yang kandidatnya tinggal satu, saring kandidat
   lain yang konflik — 26/26 huruf pulih dalam 1 ronde.
4. Decode `flag.txt` → `perhaps_the_dog_jumped_over_was_just_tired`.
   Otomasi: `python3 scripts/solve_210_spelling_quiz.py [wordlist]`.
5. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Jangan enkripsi dengan substitusi monoalfabet; gunakan cipher modern
(AES-GCM/ChaCha20-Poly1305) dengan kunci acak per pesan. Jangan pakai
ulang keystream/kunci untuk banyak plaintext.

## Takeaway LKS
Klasifikasi Cryptography: analisis frekuensi → pattern attack →
pemulihan kunci penuh dari known-plaintext massal. Relevan defensif:
mengapa ECB/substitusi deterministik bocor, dan pentingnya
randomized encryption + key hygiene.
