# basic-mod2 (Challenge 254, Cryptography)

- **ID:** 254 | **Event:** picoCTF | **Kategori:** Cryptography | **Level:** Medium
- **Flag:** `academy{1NV3R53LY_H4RD_471A6111}` (submit 201 `correct:true`)

## Skenario
File `message.txt` berisi bilangan. Tiap bilangan di-`mod 41`, lalu cari
invers modularnya (`pow(r, -1, 41)`), petakan 1-26 = A-Z, 27-36 = 0-9,
37 = `_`.

## Root Cause
Invers modular unik karena 41 prima (setiap `r != 0` punya tepat satu invers).
Pemetaan publik + modulus kecil = dekripsi deterministik tanpa kunci.
Fermat: `inv = r^39 mod 41`; Python `pow(r, -1, 41)` langsung.

## Rekonstruksi
1. Unduh `message.txt`.
2. `python3 scripts/solve_254_basic_mod2.py` → `1NV3R53LY_H4RD_471A6111`.
3. POST `/api/submissions/` → 201 correct:true.

## Mitigasi
Invers modular adalah operasi trapdoor-free; untuk kerahasiaan gunakan
kriptografi kunci (AES/RSA), bukan transformasi aritmetika publik.
