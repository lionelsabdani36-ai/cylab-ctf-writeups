# SQLiLite (Challenge 304, Web Exploitation)

- **ID:** 304 | **Event:** picoCTF 2022 | **Kategori:** Web Exploitation | **Level:** Easy (diff 2, 300 pts)
- **Flag:** `academy{L00k5_l1k3_y0u_solv3d_it_b57ed0cd}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
Form login (`login.php`, lab on-demand). Parameter `debug=1` menggemakan
query SQL mentah — bocoran struktur untuk penyerang.

## Root Cause
Interpolasi string langsung:
`SELECT * FROM users WHERE name='<u>' AND password='<p>'`.
Payload klasik `username=admin`, `password=' OR 1=1--` mengubah WHERE
menjadi `... password='' OR 1=1--'`, lolos autentikasi. Flag ada di
`<p hidden>` halaman sukses ("in plainsight").

## Rekonstruksi
1. Launch instance, buka form login.
2. POST `username=admin&password=' OR 1=1--&debug=1` ke `login.php`.
3. Ambil flag dari elemen hidden di respons.
   Otomasi: `python3 scripts/solve_304_sqlilite.py <base_url>`.

## Mitigasi
Prepared statement dengan parameter binding, matikan debug SQL di
produksi, dan jangan render secret di HTML (termasuk elemen hidden).

## Takeaway LKS
SQLi boolean klasik + enum kolom via debug echo; selalu periksa
elemen hidden setelah login berhasil.
