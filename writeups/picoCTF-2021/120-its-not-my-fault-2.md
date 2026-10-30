# 120 — It's Not My Fault 2 (picoCTF 2021, Cryptography, Medium)

## Challenge Metadata
- ID: 120 | Event: picoCTF 2021 | Author: rkm0959
- Kategori: Cryptography | Difficulty: Medium (2)
- Flag: `academy{p0lyn0m14l_4r17hm371c_73chn1qu35_4r3_u53ful_1n_m4ny_f13ld5!!!}`
- Status: SOLVED (POST /api/submissions/ -> `correct: true`)

## Problem Statement & Scope
Lab netcat on-demand (`nc chatelaine.cylabacademy.net <port>`) plus file
`not_my_fault_again.py`. Alur server: (1) MD5 proof-of-work, kirim string
berawalan prefix 5 digit yang hash md5-nya berakhir 6 hex digit target;
(2) server membangkitkan prima 512-bit p, q (GCD(p-1,q-1)==2), mencetak
`Public Modulus` n dan `Clue` e; (3) kirim `p+q` dalam 15 menit -> flag.
Kunci: e diturunkan dari CRT dengan d_p hanya 36 bit, d_q ukuran penuh,
paritas disamakan, lalu d = CRT(d_p, d_q), e = d^{-1} mod (p-1)(q-1).

## Teori & Akar Kerentanan (Root Cause)
Relasi RSA-CRT: e*d_p = 1 + k*(p-1), sehingga untuk sembarang m dengan
gcd(m,n)=1 berlaku m^(e*d_p) = m (mod p) menurut Fermat. Maka
gcd(m^(e*d_p) - m, n) = p. Serangan Pinch/Galbraith (Mathematics of Public
Key Cryptography, bag. 19.6): d_p kecil adalah akar polinomial G(x) dan bisa
dipulihkan lewat evaluasi multipoint, bukan faktorisasi n secara langsung.
Part 1 (d_p 20 bit) masih bisa brute-force paralel ~1 juta GCD; Part 2
(d_p 36 bit = 2^36 kandidat) mustahil brute-force sehingga dipecah
meet-in-the-middle: d_p = l + L*l' dengan L = 2^18. Definisikan A = m^e,
B = A^L, y_l = A^l, z_j = m*B^{-j} mod n, lalu F(x) = prod_l (x - y_l).
Untuk pasangan yang benar berlaku y_l = z_j (mod p), jadi F(z_j) habis
dibagi p dan gcd(F(z_j), n) = p. Satu evaluasi subproduct-tree (FLINT
`fmpz_mod_poly_evaluate_fmpz_vec_fast`) atas 2^18+1 titik menggantikan
2^36 GCD.

## Rekonstruksi Pengujian Terstruktur
1. Launch instance: `PUT /api/challenges/120/instance/`, poll hingga
   `RUNNING`, parse `nc host port` dari description (port 24303).
2. Unduh `not_my_fault_again.py` dari CDN challenge-files, konfirmasi
   BITS=36 dan alur PoW/CRT di atas.
3. Studi literatur: writeup Part 1 (brute-force GCD paralel) + analisis
   Galbraith/Pinch untuk Part 2 (subproduct tree + batch GCD).
4. Implementasi `nmf2.c` (gcc + libflint-dev + libgmp-dev): product tree
   F(x) derajat 262144, evaluasi cepat FLINT, scan gcd, lalu scan l untuk
   (y_l - z_j) = 0 mod p. Validasi pada kunci sintetik 128-bit (LOGL=10,
   0.05 detik, e*dp = 1 mod p-1), lalu pada kunci live (LOGL=18, 2m8s).
5. End-to-end satu koneksi (container mati saat TCP disconnect): PoW MD5
   (~7 detik) -> terima n, e -> faktorisasi in-process -> kirim p+q ->
   terima flag. Hasil: l=227565, j=19345, DP=5071403245, e*dp = 1 mod p-1.
6. Submit via `POST /api/submissions/` -> `correct: true`.

## Flag & Verifikasi
- Flag resmi: `academy{p0lyn0m14l_4r17hm371c_73chn1qu35_4r3_u53ful_1n_m4ny_f13ld5!!!}`
- Verifikasi: `201 {"challenge": 120, "correct": true, "historical": false}`

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Jangan pernah memakai eksponen CRT kecil: d_p/d_q harus ukuran penuh
  dan acak; batas 36-bit mengubah RSA-1024 menjadi masalah pencarian
  2^18 yang selesai dalam ~2 menit CPU.
- PoW MD5 6-hex-digit hanya menunda bot ~detik, bukan pertahanan.
- Time-box 15 menit tidak menghentikan serangan sub-kuadratik.
- Solver reproduktif: `scripts/solve_120_its_not_my_fault_2.py`
  (menanam `nmf2.c`, compile otomatis, PoW + faktor + kirim satu sesi).
