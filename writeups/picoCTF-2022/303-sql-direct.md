# SQL Direct (Challenge 303, Web Exploitation)

- **ID:** 303 | **Event:** picoCTF 2022 | **Kategori:** Web Exploitation | **Level:** Easy (diff 2, 200 pts)
- **Flag:** `academy{L3arN_S0m3_5qL_t0d4Y_412c85d9}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
Koneksi langsung ke PostgreSQL: `psql -h <host> -p <port> -U postgres pico`,
password `postgres` (lab on-demand, kredensial di deskripsi instance).

## Root Cause
Kredensial default + akses baca penuh ke database; flag disimpan
plain di tabel `flags` (baris Luke Skywalker). Tidak ada eksploitasi —
ini latihan enumerasi SQL.

## Rekonstruksi
1. Launch instance, catat host:port.
2. Login psql (atau pg8000): user `postgres` / db `pico`.
3. `SELECT table_name FROM information_schema.tables WHERE table_schema='public';`
4. `SELECT * FROM flags;` -> flag.
   Otomasi: `python3 scripts/solve_303_sql_direct.py <host> <port>`
   (butuh `pip install pg8000`).

## Mitigasi
Ganti kredensial default, prinsip least-privilege per role, dan jangan
simpan flag/secret di tabel yang dapat dibaca role aplikasi.

## Takeaway LKS
Enum DB standar: information_schema dulu, baru isi tabel; catat
kredensial dari deskripsi challenge sebagai bagian dari attack surface.
