# ClusterRSA (Challenge 702, Cryptography)

- **ID:** 702 | **Event:** picoCTF 2026 | **Kategori:** Cryptography | **Level:** Medium
- **Flag:** `academy{mul71_rsa_411fc267}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`message.txt`: RSA multi-prima — `n` (~1024+ bit) dengan 4 faktor prima
berbeda, `e = 65537`, `ct` = flag terenkripsi. Faktorisasi langsung
infeasible secara umum, tetapi `n` ini terdaftar di factordb (4 prima).

## Root Cause
Multi-prime RSA dengan faktor yang sudah dipublikasikan/di-share (mis.
faktor kecil atau modulus terkait di database publik) runtuh seketika:
`phi = prod(pi - 1)`, `d = inverse(e, phi)`, `m = pow(ct, d, n)`.
Pelajaran: keamanan RSA = faktorisasi harus sulit; modulus dari sumber
lemah/terpublikasi bukan kunci.

## Rekonstruksi
1. Query factordb untuk `n` → 4 faktor prima.
2. `phi = prod(p-1 for p in factors)`, `d = inverse(65537, phi)`.
3. `long_to_bytes(pow(ct, d, n))` → `academy{mul71_rsa_411fc267}`;
   cross-check `pow(m, e, n) == ct` ✓.
   Otomasi: `python3 scripts/solve_702_clusterrsa.py`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Generate prima segar dengan RNG kriptografis (p, q ≥ 1024 bit, independen),
validasi `gcd(e, phi) == 1`, dan gunakan padding OAEP — textbook RSA
rentan pada banyak serangan terkait-pesan.

## Takeaway LKS
Klasifikasi Cryptography: alur dekripsi RSA multi-prima + penggunaan
factordb sebagai oracle faktorisasi. Satu dari pola "RSA pecah tanpa
memfaktorkan sendiri" (bersama Wiener, related-message, Hastad broadcast).
