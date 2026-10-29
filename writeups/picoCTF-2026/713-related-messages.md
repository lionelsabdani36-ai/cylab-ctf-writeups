# Related Messages (Challenge 713, Cryptography)

- **ID:** 713 | **Event:** picoCTF 2026 | **Kategori:** Cryptography | **Level:** Medium
- **Flag:** `academy{m3ssage_w1th_typ0}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`chall.py`: RSA `e = 0x11` dengan dua pesan terkait — output menunjukkan
`Message - Message_fixed = -3`, `c1 = m1^e mod N`, `c2 = m2^e mod N`.
Serangan Franklin-Reiter: `g1(x) = x^e - c1` dan `g2(x) = (x+3)^e - c2`
berbagi akar `m1` atas `Z_N`; gcd keduanya linear `(x - m1)` karena
`e = 17` kecil. Tanpa memfaktorkan N.

## Root Cause
Enkripsi dua plaintext yang hubungannya diketahui (`m2 = m1 + 3`) dengan
eksponen kecil yang sama menghancurkan keamanan RSA — gcd polinomial
memulihkan pesan langsung. Pelajaran: RSA butuh padding acak (OAEP);
pesan deterministik/terkait + e kecil = Coppersmith/Franklin-Reiter.

## Rekonstruksi
1. Parse `output.txt`: baris 1 = c1, baris 2 = c2, baris 3 = delta (-3),
   baris 4 = N (2048-bit).
2. Bentuk `g1 = x^17 - c1`, `g2 = (x+3)^17 - c2` (koefisien mod N),
   Euclidean algorithm atas `Z_N` (leading coeff 1/invertibel → 17 langkah)
   sampai gcd linear.
3. `m = -a1/a0 mod N`; kandidat `m+3` decode ke
   `academy{m3ssage_w1th_typ0}` (m1 mentah kelebihan byte `z`).
   Otomasi: `python3 scripts/solve_713_related_messages.py c713/output.txt`
   (~1-2 menit, aritmetika big-int).
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
OAEP/randomized padding untuk setiap enkripsi RSA; jangan enkripsi dua
pesan berhubungan dengan parameter sama; gunakan e = 65537 + padding.

## Takeaway LKS
Klasifikasi Cryptography: serangan related-message Franklin-Reiter —
implementasi GCD polinomial mod N dari nol (pmul/psub/pmod). Pola "RSA
tanpa padding" bersama Hastad broadcast & Wiener.
