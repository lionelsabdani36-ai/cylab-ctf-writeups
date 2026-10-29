# Secrets (Challenge 296, Web Exploitation)

- **ID:** 296 | **Event:** picoCTF 2022 | **Kategori:** Web Exploitation | **Level:** Easy (diff 2, 200 pts)
- **Flag:** `academy{succ3ss_@h3n1c@10n_2389750f}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
"Beberapa halaman tersembunyi. Temukan yang berisi flag."
(lab on-demand; hint: folders folders folders).

## Root Cause
Tiap halaman mereferensikan folder tersembunyi berikutnya lewat aset:
`/` (`secret/assets/index.css`) -> `/secret/` (`hidden/file.css`)
-> `/secret/hidden/` (`superhidden/login.css`)
-> `/secret/hidden/superhidden/` berisi `<h3 class="flag">`.
Security-by-obscurity berlapis tanpa kontrol akses.

## Rekonstruksi
1. Launch instance, buka base URL, view-source.
2. Ikuti rantai direktori dari atribut `href`/`src`.
3. Baca source halaman terakhir (CSS mungkin menyembunyikan visual,
   flag tetap di HTML).
   Otomasi: `python3 scripts/solve_296_secrets.py <base_url>`.

## Mitigasi
Akses harus ditegakkan server-side per-resource; path tersembunyi
tanpa autentikasi sama dengan publik.

## Takeaway LKS
Enum direktori berlapis: selalu view-source tiap level dan anggap
komentar/atribut aset sebagai peta.
