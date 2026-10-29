# Safe Opener (Challenge 294, Reverse Engineering)

- **ID:** 294 | **Event:** picoCTF 2022 | **Kategori:** Reverse Engineering | **Level:** Easy (diff 2, 100 pts)
- **Flag:** `academy{pl3as3_l3t_m3_1nt0_th3_saf3}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`SafeOpener.java` meminta password brankas, lalu membandingkannya.

## Root Cause
`main()` me-base64-encode input lalu `openSafe()` membandingkannya dengan
konstanta `encodedkey = "cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz"`.
Konstanta itu sendiri adalah base64 dari password — decode langsung
membuka brankas: `pl3as3_l3t_m3_1nt0_th3_saf3`.

## Rekonstruksi
1. Unduh `SafeOpener.java` dari CDN (URL di instance description).
2. `echo '<b64>' | base64 -d` -> password.
3. Bungkus `academy{...}` sesuai instruksi challenge.
   Otomasi: `python3 scripts/solve_294_safe_opener.py`.

## Mitigasi
Encoding bukan enkripsi; simpan verifier hash garam di server dan
jangan kirim pembanding rahasia ke klien dalam bentuk apapun.

## Takeaway LKS
Bedakan encode vs encrypt; konstanta perbandingan di biner/source
sering kali ADALAH rahasianya — `strings` + decode dulu sebelum reversing.
