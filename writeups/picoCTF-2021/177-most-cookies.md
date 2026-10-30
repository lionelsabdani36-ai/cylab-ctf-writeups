# 177 - Most Cookies (Web Exploitation, picoCTF 2021, Medium)

## Challenge Metadata
- ID: 177 | Event: picoCTF 2021 | Author: Ryan Ramseyer / picoCTF
- Category: Web Exploitation | Difficulty: Medium (2)
- Flag: `academy{cO0ki3s_yum_7ea44b33}`

## Problem Statement & Scope
Lab on-demand: aplikasi Flask (`server.py` publik, 28 nama cookie hard-coded).
`app.secret_key = random.choice(cookie_names)` lalu dicetak ke stdout
server (tidak terlihat pemain). Session `very_auth=blank` default;
`/search` hanya menerima 27 nama cookie valid; `/display` memberi flag
hanya bila `very_auth == "admin"` (string yang tidak pernah diberikan
legit). Tugas: tempa session cookie Flask bertanda tangan valid.

## Teori & Akar Kerentanan (Root Cause)
1. Flask session = JWS itsdangerous: `b64(payload).b64(ts).b64(HMAC)`,
   kunci turunan `HMAC-SHA1(secret, b"cookie-session")` (`key_derivation`
   default `hmac`, digest SHA1). Siapa pun tahu secret bisa menandatangani
   payload arbitrer (CWE-798 hard-coded secret + CWE-330 entropi lemah:
   hanya 28 kandidat).
2. Secret space 28 kata bahasa Inggris = brute force offline instan:
   ambil satu cookie live `{"very_auth":"blank"}` dari `GET /`, cocokkan
   tanda tangan terhadap 28 kandidat, pemenang = `wafer`.
3. Verifikasi timestamp itsdangerous memakai waktu server; memakai ulang
   timestamp live menghindari kedaluwarsa.

## Rekonstruksi Eksploitasi Step-by-Step
1. `PUT /api/challenges/177/instance/` -> RUNNING
   `chatelaine.cylabacademy.net:11042`, unduh `server.py` dari CDN.
2. `GET /` via socket mentah, simpan `Set-Cookie: session=...`
   (`{"very_auth":"blank"}`).
3. Kalibrasi skema: `django-concat` (`SHA1(salt+signer+secret)`) GAGAL
   untuk semua 28; `HMAC(secret, salt)` MATCH pada `wafer`.
4. Tempa `{"very_auth":"admin"}` + timestamp live + HMAC baru,
   `GET /display` dengan cookie palsu -> 200 + flag di HTML.
5. Submit `POST /api/submissions/` -> `correct: true`; `DELETE` instance.

## Flag & Verifikasi
- `academy{cO0ki3s_yum_7ea44b33}` (`correct: true`, historical false).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Secret Flask dari secret manager / env 256-bit (`secrets.token_hex(32)`),
  bukan daftar kata di source; jangan pernah cetak secret ke log.
- Otorisasi `admin` wajib cek server-side (DB/role), bukan nilai cookie
  yang bisa ditempa klien.
- Defensif: rotasi secret berkala, set `PERMANENT_SESSION_LIFETIME`
  pendek + `SESSION_COOKIE_HTTPONLY/Secure`, alert anomali decode gagal.
