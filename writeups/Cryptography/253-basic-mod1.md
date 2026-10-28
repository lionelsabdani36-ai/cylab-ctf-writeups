# basic-mod1 (Challenge 253, Cryptography)

- **ID:** 253 | **Event:** picoCTF | **Kategori:** Cryptography | **Level:** Medium
- **Flag:** `academy{R0UND_N_R0UND_65371195}` (submit 201 `correct:true`)

## Skenario
File `message.txt` berisi deretan bilangan bulat. Skema dekripsi: tiap bilangan
di-`mod 37` lalu dipetakan ke karakter: 0-25 = A-Z, 26-35 = 0-9, 36 = `_`.

## Root Cause
Aritmetika modular sebagai substitusi monoalfabetik: `mod 37` memampatkan
ruang bilangan ke 37 simbol. Tanpa kunci, pemetaan publik membuat dekripsi
trivial — keamanan nol, murni encoding.

## Rekonstruksi
1. Unduh `message.txt` dari CDN challenge-files.
2. `python3 scripts/solve_253_basic_mod1.py` → tiap token `int(t) % 37`
   dipetakan via charset → `R0UND_N_R0UND_65371195`.
3. Bungkus `academy{...}`, POST `/api/submissions/` → 201 correct:true.

## Mitigasi
Untuk data sensitif gunakan cipher terautentikasi (AES-GCM); jangan merancang
"cipher" substitusi sendiri untuk proteksi nyata.
