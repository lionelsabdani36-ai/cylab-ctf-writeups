# rail-fence (Challenge 289, Cryptography)

- **ID:** 289 | **Event:** picoCTF | **Kategori:** Cryptography | **Level:** Medium
- **Flag:** `academy{WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_D3AB175F}` (submit 201 `correct:true`)

## Skenario
Cipherteks rail-fence 4 rel di `message.txt`. Pesan terdekripsi menyebut
frasa flag secara langsung.

## Root Cause
Transposisi zig-zag periodik: urutan baca kolom ditentukan pola rel yang
deterministik. Dengan jumlah rel diketahui, dekripsi = menempatkan kembali
karakter sesuai pola — tanpa kunci, tanpa kerahasiaan.

## Rekonstruksi
1. Unduh `message.txt` (56 char).
2. `python3 scripts/solve_289_rail_fence.py` → pola zig-zag 4 rel →
   `The flag is: WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_D3AB175F`.
3. POST `/api/submissions/` → 201 correct:true.

## Mitigasi
Transposisi klasik rapuh terhadap analisis pola; gunakan cipher modern
(AES-GCM/ChaCha20-Poly1305) untuk kerahasiaan nyata.
