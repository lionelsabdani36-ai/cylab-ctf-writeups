# Small Trouble (Challenge 718, Cryptography)

- **ID:** 718 | **Event:** picoCTF 2026 | **Kategori:** Cryptography | **Level:** Medium
- **Flag:** `academy{sm4ll_d_46c3352b}` (recovered lokal + roundtrip `pow(m,e,n)==c` OK;
  submit API pending — sesi kedaluwarsa, kirim ulang dengan cookie segar)

## Skenario
`encryption.py`: RSA dengan `p`, `q` 1048-bit (n ~2096 bit) tetapi
`d = getPrime(256)` — eksponen privat hanya 256 bit, jauh di bawah batas
Wiener (`d < N^0.25/3` ≈ 2^500; di sini `d` ≈ 2^256). Serangan pecahan
berlanjut (continued fraction) atas `e/N` memulihkan `k/d`.

## Root Cause
`e*d ≡ 1 (mod phi)` → `e/N ≈ k/d` dengan pendekatan sangat baik saat d
kecil; konvergen pecahan-berlanjut `e/N` memuat `k/d`, lalu
`phi = (e*d-1)/k`, `s = N - phi + 1 = p+q`, diskriminan `s²-4N` kuadrat
sempurna → p, q, dekripsi. Pelajaran: d kecil = optimasi dekripsi yang
fatal; d harus ≈ seukuran N (atau pakai CRT-dp/dq dengan p, q aman).

## Rekonstruksi
1. Parse `message.txt` (n, e, c).
2. Konvergen `e/N`; untuk tiap `(k, d)`: jika `(e*d-1) % k == 0` →
   `phi = (e*d-1)/k`, `s = n-phi+1`, cek `s²-4n` kuadrat sempurna dan
   `(s+t)` genap → `p*q == n` ✓ (d 256-bit ketemu).
3. `m = pow(c, d, n)` → `academy{sm4ll_d_46c3352b}`;
   verifikasi `pow(m, e, n) == c` ✓.
   Otomasi: `python3 scripts/solve_718_small_trouble.py c718/message.txt`.
4. Submit `POST /api/submissions/` → (tunggu sesi segar).

## Mitigasi
Gunakan d penuh (≈ N) atau CRT dengan prima kuat; validasi otomatis
`d > N^0.25` saat generate kunci; padding OAEP tetap wajib.

## Takeaway LKS
Klasifikasi Cryptography: serangan Wiener — implementasi konvergen
pecahan-berlanjut + pemulihan phi/pq dari nol. Pola "parameter RSA
kekecilan" bersama e kecil & Hastad.
