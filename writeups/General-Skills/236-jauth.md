# JAuth (Challenge 236, Web Exploitation)

- **ID:** 236 | **Event:** CyLab Gym (tanpa event) | **Kategori:** Web Exploitation / JWT Authentication Flaw | **Level:** Medium
- **Flag:** `academy{succ3ss_@u7h3nt1c@710n_99bf4b72}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
"Our Bank": login `test`/`Test123!` di `/auth` memberi cookie JWT
HS256 `{role: user}`. `/private` untuk user hanya halaman testing;
admin melihat flag inline.

## Root Cause
Verifikator JWT menerima `alg: none` — token tanpa signature dengan
body `{role: admin}` lolos sebagai admin. Trust pada klaim
client-side tanpa verifikasi kriptografi = broken access control
(OWASP API2:2023 / CWE-327, CWE-639).

## Rekonstruksi
1. Start instance: `PUT /api/challenges/236/instance/` → catat URL
   `chatelaine.cylabacademy.net:<port>`; login test/Test123!.
2. Decode JWT cookie, ganti `role` → `admin`, header → `alg: none`,
   kirim tanpa signature ke `/private`.
3. Halaman admin memuat flag inline. Otomasi:
   `python3 scripts/solve_236_jauth.py [base_url]`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).
   Instance di-STOP setelah solve (slot on-demand tunggal).

## Mitigasi
Whitelist algoritma di server (`HS256` saja, tolak `none`); pin
kunci/JWKS, validasi `exp`/`aud`/`iss`; otorisasi berbasis sesi
server-side, bukan klaim role dari klien.

## Takeaway LKS
Klasifikasi Web Exploitation: anatomi JWT (header.payload.signature),
serangan algorithm-confusion/none-alg, dan prinsip never-trust-client.
Relevan defensif: audit konfigurasi library JWT (PyJWT `algorithms=[...]`).
