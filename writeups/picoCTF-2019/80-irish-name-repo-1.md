# Writeup: Irish-Name-Repo 1 (Challenge ID: 80)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / SQL Injection
- **Difficulty:** Medium
- **Author:** Chris Hensler
- **Event:** picoCTF 2019
- **Points:** 300
- **Flag:** `academy{s0m3_SQL_d3fba797}`

---

## Problem Statement & Scope
Situs "List 'o the Irish!" dengan form login (`login.html` → `login.php`) berkueri SQLite. Parameter `debug=1` membuat server membocorkan kueri SQL yang dijalankan — orakel sempurna untuk crafting payload.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **String-interpolated SQL:** input pengguna disambung langsung ke kueri tanpa prepared statement, sehingga kutip tunggal `'` dapat keluar dari konteks string.
2. **Auth bypass klasik:** `username=' OR 1=1-- -` menutup literal username, menyuntik kondisi selalu-benar, dan mengomentari sisa kueri (cek password) — login berhasil sebagai baris pertama tabel (admin).
3. **Debug leak sebagai orakel:** respons `SQL query: SELECT ...` mengonfirmasi struktur kueri dan keberhasilan injeksi sebelum flag ditampilkan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Provision instance, crawl link (`login.html`), identifikasi field `username`/`password`/`debug`.
2. POST `username=' OR 1=1-- -`, `password=' OR 1=1-- -`, `debug=1` ke `login.php`.
3. Respons: `<h1>Logged in!</h1>` + `Your flag is: academy{s0m3_SQL_d3fba797}`.
4. Submit flag via API.

---

## Flag & Verifikasi
- **Flag:** `academy{s0m3_SQL_d3fba797}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Gunakan prepared statement / parameter binding** di semua kueri; jangan pernah interpolasi input.
- **Matikan debug/error SQL** di produksi — bocoran kueri mempercepat eksploitasi.
- **Prinsip least privilege:** akun DB aplikasi jangan punya hak baca tabel sensitif berlebih.

---

## Solver
Lihat `scripts/solve_80_irish_name_repo_1.py` — mengirim payload auth-bypass dan mengekstrak flag dari respons.
