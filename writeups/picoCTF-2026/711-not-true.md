# Not TRUe (Challenge 711, Cryptography)

- **ID:** 711 | **Event:** picoCTF 2026 | **Kategori:** Cryptography | **Level:** Hard
- **Flag:** `academy{th4ts_s0_N0t_TRU3_d78e9bcb}` (serangan lattice + dekripsi lokal OK;
  submit API `{"correct": true}` status 201)

## Skenario
`encrypt.py` mengimplementasikan NTRU textbook (N=48, p=3, q=509):
`h = p·f_q⁻¹·g (mod q)`, `ct = p·h·r + m (mod q)`.
`public.txt` hanya memberi h dan 6 blok ciphertext. Flag di-encode
bit-per-karakter (MSB-first) menjadi polinomial biner 48-koefisien.

## Root Cause
Keamanan NTRU bertumpu pada sulitnya Shortest Vector Problem (SVP) di
lattice konvolusi 2N-dimensi. Untuk parameter mainan (N=48, q=509),
lattice berbaris `[I | C(h)]`, `[0 | qI]` (C(h) matriks konvolusi siklik
h) memuat vektor rahasia pendek (f, g). Algoritma LLL menemukannya dalam
milidetik — serangan klasik Coppersmith–Shamir pada parameter NTRU-1990an
yang lemah. Kunci LLL ekuivalen hingga rotasi siklik dan tanda karena
`x^k·f` konjugat valid di `R = Z[x]/(x^N−1)`.

## Rekonstruksi
1. Unduh `encrypt.py` + `public.txt` dari endpoint file statis.
2. Bangun lattice 96×96 (fpylll), reduksi LLL → kandidat (f, g') dengan
   `max|f|≤2`, `max|f·h mod q|≤4` (47 kandidat).
3. Untuk tiap kandidat × tanda × 48 rotasi: inversi `f (mod p, x^N−1)`
   via extended Eucldiean di GF(3)[x], lalu dekripsi
   `a=center(f·ct mod q)`, `m=f_p⁻¹·(a mod p)`.
4. Rotasi 0 / tanda +1 menghasilkan ASCII printable berisi flag.
5. Submit `POST /api/submissions/` → `{"correct": true}` (201).
   Otomasi: `python3 scripts/solve_711_not_true.py` (butuh `pip install fpylll`).

## Mitigasi
Jangan pakai parameter lattice mainan di produksi (NIST PQC: ML-KEM/Kyber
terstandar dengan parameter yang dianalisis ketat). LLL menghancurkan NTRU
berdimensi kecil — dimensi adalah parameter keamanan, bukan sekadar performa.

## Takeaway LKS
Klasifikasi Cryptography: serangan lattice pada NTRU — konstruksi basis
Coppersmith–Shamir + LLL + resolusi ambiguitas rotasi/tanda. Pola
"kunci privat pulih dari informasi publik".
