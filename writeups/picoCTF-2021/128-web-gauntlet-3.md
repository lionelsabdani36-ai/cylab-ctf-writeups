# Writeup: Web Gauntlet 3 (Challenge ID: 128)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / SQL Injection
- **Difficulty:** Medium
- **Author:** madStacks
- **Event:** picoCTF 2021
- **Points:** 300
- **Flag:** `academy{k3ep_1t_sh0rt_2e11b173}`

---

## Problem Statement & Scope
"Filtered SQLite Injection Challenge #3": login dengan filter `or and true false union like = > < ; -- /* */ admin` dan batas gabungan username+password 25 karakter. Flag ada di komentar `filter.php`, terlihat setelah session `winner3=1`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Bypass kata `admin`:** gabung string SQLite `ad'||'min` (11 char) — operator `||` tidak difilter, sehingga kueri melihat username `admin` tanpa literal yang diblokir.
2. **Bypass kebutuhan password:** `=` dan `LIKE` diblokir, tetapi `GLOB` tidak. Password `' GLOB '*` membuat kondisi `password='' GLOB '*'` — pola `*` cocok dengan string apa pun termasuk kosong → TRUE.
3. **Kueri akhir:** `... WHERE username='ad'||'min' AND password='' GLOB '*'` valid di SQLite dan mengembalikan baris admin; server menampilkan "Congrats! You won!" dan menandai session menang. GET `filter.php` dengan session menang menampilkan source + flag di komentar.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Provision instance, baca `/filter.php` untuk daftar blokir.
2. POST `user=ad'||'min`, `pass=' GLOB '*` ke `index.php` (pertahankan cookie session).
3. Respons: "Congrats! You won! Check out filter.php".
4. GET `filter.php` dengan session yang sama → komentar `// academy{k3ep_1t_sh0rt_2e11b173}`.
5. Submit via API → `correct: true`.

---

## Flag & Verifikasi
- **Flag:** `academy{k3ep_1t_sh0rt_2e11b173}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Blocklist tidak pernah cukup:** selalu ada operator alternatif (`GLOB`, `IS`, `||`); gunakan allowlist + prepared statement.
- **Batas panjang ≠ keamanan:** payload 11+9 char menembus batas 25 char — uji batas dengan payload minimal.
- **Jangan taruh flag di source yang dapat dibaca** setelah kondisi menang; prinsipnya sama dengan proteksi endpoint debug.

---

## Solver
Lihat `scripts/solve_128_web_gauntlet_3.py` — login bypass dua-field lalu membaca flag dari filter.php.
