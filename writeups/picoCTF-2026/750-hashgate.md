# 750 - Hashgate (Web Exploitation, picoCTF 2026, Medium)

## Challenge Metadata
- ID: 750 | Event: picoCTF 2026
- Category: Web Exploitation | Difficulty: Medium (2)
- Flag: `academy{id0r_unl0ck_cbbb8f45}`

## Problem Statement & Scope
Portal organisasi: form login (`POST /login` JSON email/password)
me-redirect ke halaman profil `/profile/user/<hash>`. Kredensial
`guest@cylabacademy.org / guest` tertinggal di komentar HTML. Sekitar
20 karyawan; profil admin menyembunyikan flag. Tidak ada session
cookie — otorisasi hanya bertumpu pada ketidak-tertebakan URL hash.

## Teori & Akar Kerentanan (Root Cause)
- Insecure Direct Object Reference (CWE-639) + security by obscurity
  (CWE-656): ID profil disamarkan sebagai MD5 tanpa secret, tanpa
  verifikasi sesi server-side. Siapa pun bisa menghitung
  `md5("3010")` dan membuka profil admin.
- MD5 integer kecil dapat dienumerasi penuh dalam milidetik
  (ruang ~5000 kandidat); one-way function tanpa salt/pepper dan
  tanpa rate limit tidak menghentikan enumerasi.
- Kredensial guest di komentar HTML memberi titik pijak awal
  (information exposure, CWE-615).

## Rekonstruksi Eksploitasi Step-by-Step
1. Launch instance (`PUT /api/challenges/750/instance/`), buka web.
2. Baca sumber halaman: kredensial guest di komentar HTML.
3. `POST /login` JSON guest -> redirect
   `/profile/user/e93028bdc1aacdfb3687181f2031765d`
   (`md5("3000")`, profil Guest ID 3000, tanpa cookie sesi).
4. Enum ID 2980-3020 + 1-59 via `md5(str(i))`, GET tiap profil.
5. HIT: ID 3010 (`22722a343513ed45f14905eb07621686`):
   `Welcome, admin! Here is the flag: academy{id0r_unl0ck_cbbb8f45}`.
6. Submit `POST /api/submissions/` -> `correct: true`; `DELETE` instance.

## Flag & Verifikasi
- `academy{id0r_unl0ck_cbbb8f45}` (`correct: true`).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Otorisasi harus server-side per-request (session/token + cek peran),
  bukan URL "rahasia".
- Gunakan identifier acak tak-tertebak (UUIDv4) + tetap cek sesi;
  hash deterministik dari integer kecil bukan kontrol akses.
- Jangan tinggalkan kredensial di komentar HTML; terapkan rate limit
  dan monitoring enumerasi.
