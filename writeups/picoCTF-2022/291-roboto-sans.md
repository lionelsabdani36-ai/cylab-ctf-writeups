# Roboto Sans (Challenge 291, Web Exploitation)

- **ID:** 291 | **Event:** picoCTF 2022 | **Kategori:** Web Exploitation | **Level:** Easy (diff 2, 200 pts)
- **Flag:** `academy{Who_D03sN7_L1k5_90B0T5_662b27d3}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
"Flag ada di aplikasi web, belum tentu di website." Lab on-demand
(`PUT /api/challenges/291/instance/`, URL rotasi per launch).

## Root Cause
`/robots.txt` membocorkan jalur tersembunyi dalam base64:
`anMvbXlmaWxlLnR4dA==` = `js/myfile.txt`. `flag1.txt` hanya pengecoh.

## Rekonstruksi
1. Launch instance, catat base URL.
2. `GET /robots.txt` -> decode entri base64 -> `js/myfile.txt`.
3. `GET /js/myfile.txt` -> flag.
   Otomasi: `python3 scripts/solve_291_roboto_sans.py <base_url>`.

## Mitigasi
Jangan simpan konten sensitif di path yang didaftar robots.txt
(itu peta bagi penyerang); sajikan 404 seragam dan audit file publik.

## Takeaway LKS
Enum web: robots.txt/sitemap adalah recon pasif pertama; decode setiap
string mencurigakan sebelum menilai "tidak ada apa-apa".
