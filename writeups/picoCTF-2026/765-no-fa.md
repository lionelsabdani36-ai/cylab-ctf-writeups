# No FA (Challenge 765, Web Exploitation)

- **ID:** 765 | **Event:** picoCTF 2026 | **Kategori:** Web Exploitation / Auth & 2FA | **Level:** Medium
- **Flag:** `academy{n0_r4t3_n0_4uth_96369057}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
Aplikasi Flask login + OTP 4-digit. Dua artefak bocor via CDN: `app.py`
(source penuh) dan `users.db` (SQLite 20 user: hash SHA-256, kolom
`two_fa`; hanya `admin` yang `two_fa=1`). Flag hanya dirender di `/`
ketika `session['username'] == 'admin'` dan `logged == 'true'`.
Lab on-demand `xebec.cylabacademy.net:37505`.

## Root Cause
Tiga cacat berlapis: (1) password disimpan sebagai SHA-256 **tanpa salt**
dan DB-nya bocor — hash admin `c20fa1...` langsung crack dengan rockyou
menjadi `apple@123` (tanpa salt, satu tabel hujan menelan semua user);
(2) OTP 2FA hanya 4 digit (`randint(1000,9999)`, 9000 kandidat) dengan
window 120 detik tetapi **tanpa rate-limit** di `POST /two_fa` —
brute-force habis dalam ~60 detik; (3) OTP disimpan di session cookie
client-side Flask tanpa penguncian percobaan, sehingga race 50 thread
terhadap SATU sesi selalu menang sebelum window kedaluwarsa. Pelajaran:
2FA yang bisa di-enumerasi habis tanpa throttle sama dengan No FA.

## Rekonstruksi
1. Unduh `app.py` + `users.db` dari CDN; baca skema SQLite.
2. Crack offline: `sha256(rockyou) == <hash>` → `john.doe:apple123`,
   `admin:apple@123` (2/20 crack, sisanya tidak diperlukan).
3. Launch lab: `PUT /api/challenges/765/instance/` → tunggu `RUNNING`.
4. Login `admin:apple@123` (satu sesi!), lalu race 50 thread
   `POST /two_fa` `0000`-`9999` dalam sesi yang sama. OTP pemenang live:
   `8863`. `GET /` → flag. Otomasi:
   `python3 scripts/solve_765_no_fa.py [base_url]`.
   Jebakan: sesi paralel = OTP berbeda per sesi, 10 worker sekuensial
   gagal total; satu sesi + 50 thread menang dalam 1x jalan.
5. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Hash password dengan bcrypt/argon2 + salt acak per user; jangan pernah
distribusikan `users.db`. Throttle OTP (maks 5 percobaan + lockout +
backoff eksponensial), OTP 6-8 digit dari CSPRNG (`secrets`), window
pendek (30-60 detik), dan invalidasi OTP setelah 1x pakai. Pisahkan
flag/secret dari template logic ke kontrol akses server-side sejati.

## Takeaway LKS
Klasifikasi Web Exploitation: analisis source Flask, forensik SQLite
bocor, cracking hash unsalted (rockyou + sha256), audit logika 2FA,
race-condition brute-force ber-window waktu. Rantai crypto-lemah +
auth-tanpa-throttle ini pola favorit modul Web di LKS Cyber Security.
