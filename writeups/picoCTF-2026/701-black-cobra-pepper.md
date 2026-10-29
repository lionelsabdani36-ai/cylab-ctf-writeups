# Black Cobra Pepper (Challenge 701, Cryptography)

- **ID:** 701 | **Event:** picoCTF 2026 | **Kategori:** Cryptography | **Level:** Medium
- **Flag:** `academy{spi1cy!}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`chall.py` mengklaim AES-128, tetapi `sub_bytes()`, `sub_word()`, dan
`rcon()` semuanya fungsi identitas — S-box (satu-satunya komponen
non-linear AES) hilang. `output.txt` memberi satu pasangan known-plaintext
(`pt1 = "randomdata1111111"` hex → `ct1`) plus `ct2` = flag terenkripsi.

## Root Cause
Tanpa S-box, setiap operasi tersisa (AddRoundKey, ShiftRows, MixColumns,
key schedule) adalah linear atas GF(2). Seluruh cipher menjadi peta AFIN:
`E_k(pt) = L(pt) XOR F(k)` dengan `L` tak tergantung kunci. Kunci nol adalah
titik tetap key schedule (split/rot/xor/glue dari nol = nol), jadi
`L(pt) = E_0(pt)` langsung dapat dihitung, lalu
`flag = D_0(ct2 XOR ct1 XOR E_0(pt1))` dengan `D_0` = dekripsi kunci-nol
(MixColumns/ShiftRows invertibel, AddRoundKey involusi).
Pelajaran: keamanan AES bertumpu pada S-box; cipher "AES minus S-box"
adalah sistem linear yang pecah dengan satu pasangan known-plaintext.

## Rekonstruksi
1. Port `chall.py` ke solver (buang dependensi `pwn`), implementasi
   `enc`/`dec` generik + `inv_mix_columns` (koefisien 0e/0b/0d/09).
2. Hitung `F(k) = ct1 XOR E_0(pt1)`, lalu
   `flag = D_0(ct2 XOR F(k))` → `academy{spi1cy!}`.
   Otomasi: `python3 scripts/solve_701_black_cobra_pepper.py`.
3. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Jangan memodifikasi primitif kripto standar; gunakan library teruji
(AES-GCM/ChaCha20-Poly1305). Uji linearitas (avalanche) sebagai smoke test:
satu bit input harus mengubah ~setengah bit output.

## Takeaway LKS
Klasifikasi Cryptography: mengenali cipher afin vs non-linear, inversi
round cipher (ShiftRows/MixColumns), dan eksploitasi known-plaintext pada
sistem linear — pola yang sama dipakai di serangan slide/linear cryptanalysis.
