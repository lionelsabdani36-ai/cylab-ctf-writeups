# bloat.py (Challenge 256, Reverse Engineering)

- **ID:** 256 | **Event:** picoCTF 2022 | **Kategori:** Reverse Engineering / Obfuscation | **Level:** Medium
- **Flag:** `academy{d30bfu5c4710n_f7w_d77083fe}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`bloat.py` meminta password, lalu XOR-decrypt `flag.txt.enc` dengan
kunci turunan bila password benar. Semua nama fungsi/variabel
diacak (`arg133`, `arg432`), password dan kunci disembunyikan sebagai
aritmetika indeks ke string alfabet.

## Root Cause
Alfabet `a = chr(33)..chr(126) + chr(32)`; password adalah
`a[71]+a[64]+a[79]+a[79]+a[88]+a[66]+a[71]+a[64]+a[77]+a[66]+a[68]`
= `happychance`, kunci XOR adalah
`a[81]+a[64]+a[79]+a[82]+a[66]+a[64]+a[75]+a[75]+a[72]+a[78]+a[77]`
= `rapscallion` (fungsi `arg122` mengulang kunci sepanjang plaintext).
Obfuscation indeks mudah di-evaluasi statis — verifikasi live
menghitung indeks yang sama dan XOR-decrypt 35-byte `flag.txt.enc`.

## Rekonstruksi
1. Unduh `bloat.py` + `flag.txt.enc` dari CDN challenge-files.
2. Evaluasi indeks alfabet → password `happychance`, kunci
   `rapscallion`.
3. XOR-decrypt enc dengan kunci berulang → flag. Otomasi:
   `python3 scripts/solve_256_bloat.py [flag.txt.enc]`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Jangan embed password/kunci di kode client; lakukan verifikasi dan
dekripsi di server. Bila offline tak terhindarkan, gunakan KDF
(Argon2/scrypt) + AEAD, bukan XOR kunci-statis yang reversibel.

## Takeaway LKS
Klasifikasi Reverse Engineering: de-obfuscation aritmetika indeks,
evaluasi ekspresi Python statis, dan serangan repeating-XOR.
Relevan defensif: perbedaan obfuscation vs enkripsi, dan bahaya
secret di kode yang didistribusikan.
