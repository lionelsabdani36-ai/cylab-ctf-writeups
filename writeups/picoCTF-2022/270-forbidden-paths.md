# Forbidden Paths (Challenge 270, Web Exploitation)

- **ID:** 270 | **Event:** picoCTF 2022 | **Kategori:** Web Exploitation / Path Traversal | **Level:** Medium
- **Flag:** `academy{7h3_p47h_70_5ucc355_afd5d939}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
Lab on-demand "Web eReader": form `POST read.php` dengan field `filename` membaca file dari `/var/www/html/`. Filter menolak absolute path (`/flag.txt` -> "Not Authorized"). Flag di `/flag.txt`.

## Root Cause
Validasi blacklist parsial: hanya path absolut yang ditolak, traversal relatif `../` lolos (CWE-22 Improper Limitation of a Pathname). Web root 3 level di bawah `/`, sehingga `../../../flag.txt` keluar ke root dan membaca flag. Referensi: NIST SP 800-115 (directory traversal testing), OWASP A01 Broken Access Control.

## Rekonstruksi
1. Launch lab: `PUT /api/challenges/270/instance/`, poll hingga `RUNNING`, ambil URL `http://xebec.cylabacademy.net:<port>/`.
2. Baseline: `filename=divine-comedy.txt` -> isi Gutenberg; `filename=/flag.txt` -> "Not Authorized" (filter terkonfirmasi).
3. Traversal: `../flag.txt` dan `../../flag.txt` -> "File does not exist"; `../../../flag.txt` -> `academy{7h3_p47h_70_5ucc355_afd5d939}`.
   Otomasi: `python3 scripts/solve_270_forbidden_paths.py <lab_url>`.
4. Submit `POST /api/submissions/` -> `correct: true` (live 2026-10-30). Instance di-terminate setelah solve.

## Mitigasi
Canonicalize path (`realpath`) lalu enforce prefix jail `/var/www/html/`; gunakan allowlist basename tanpa separator; jalankan dengan chroot/read-only mount agar traversal tidak mencapai `/flag.txt`.

## Takeaway LKS
Klasifikasi Web: identifikasi filter -> uji bypass traversal bertingkat -> eksfiltrasi file. Relevan defensif: bedakan blacklist vs allowlist, dan pentingnya canonicalization sebelum otorisasi path.
