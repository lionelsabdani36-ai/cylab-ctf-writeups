# Search source (Challenge 295, Web Exploitation)

- **ID:** 295 | **Event:** picoCTF 2022 | **Kategori:** Web Exploitation | **Level:** Easy (diff 2, 100 pts)
- **Flag:** `academy{1nsp3ti0n_0f_w3bpag3s_f44abb87}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
Developer meninggalkan artefak penting di source website (lab on-demand).

## Root Cause
Flag tertanam di `css/style.css` yang disajikan publik tanpa proteksi.
Petunjuk "mirror website lalu gunakan tool pencarian" mengarah ke
`wget -rk` + `grep -r`.

## Rekonstruksi
1. Launch instance, catat base URL.
2. `wget -rk -np <base>` untuk mirror.
3. `grep -r -o -E 'academy\{[^}]*\}' .` -> `css/style.css`.
   Otomasi: `python3 scripts/solve_295_search_source.py <base_url>`.

## Mitigasi
Jangan commit secret ke aset statis; pindai build artifact dengan
secret-scanner (gitleaks/trufflehog) di CI sebelum deploy.

## Takeaway LKS
Source-review sistematis: mirror penuh lalu grep pola flag lebih andal
daripada klik manual file-per-file di DevTools.
