# Writeup: login (Challenge ID: 200)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Client-Side Authentication Bypass
- **Difficulty:** Medium
- **Event:** picoMini by redpwn
- **Flag:** `picoCTF{53rv3r_53rv3r_53rv3r_53rv3r_53rv3r}`

---

## Problem Statement & Scope

Halaman login statis di `login.mars.cylabacademy.net`: form HTML
(`username` + `password`, `method="POST"`) tanpa backend visible.
Seluruh logika autentikasi berada di file `index.js` sisi klien.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Client-side authentication:** keputusan login dibuat penuh di
   browser (`addEventListener("submit")` + `preventDefault()`), bukan
   di server. Siapa pun bisa membaca syarat lolosnya via view-source.
2. **Hardcoded credential hash:** username/password pembanding disimpan
   langsung di JS sebagai string base64 tanpa padding
   (`btoa(value).replace(/=/g,"")`). Membalik base64 = kredensial bocor.
3. **Flag sebagai password:** password yang diharapkan *adalah* flag itu
   sendiri (`picoCTF{...}` di-base64), jadi decode satu baris = solve.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. `GET /` → form login statis; catat `script src="index.js"`.
2. `GET /index.js` → handler submit membandingkan
   `btoa(username)=="YWRtaW4"` dan `btoa(password)=="cGljb0..."`.
3. Decode base64 (tambah padding `=`): user `admin`,
   flag `picoCTF{53rv3r_53rv3r_53rv3r_53rv3r_53rv3r}`.
4. Solver `scripts/solve_200_login.py` otomatis fetch `index.js`,
   ekstrak token via regex, decode, cetak flag.
5. Submit via API → `{"correct": true}` (HTTP 201). Catatan: format
   `academy{...}` ditolak verifier untuk challenge ini; flag native
   `picoCTF{...}` yang diterima.

---

## Flag & Verifikasi

- **Flag:** `picoCTF{53rv3r_53rv3r_53rv3r_53rv3r_53rv3r}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan
  `{"correct": true}` (HTTP 201);
  `solved_by_user: true` pada `GET /api/challenges/200/`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- Jangan pernah menaruh keputusan autentikasi atau secret di JavaScript
  klien — validasi kredensial wajib di server (session/token HttpOnly).
- Secret/kredensial hardcode di artefak statis = bocor by-design;
  simpan di secret manager, hash password dengan bcrypt/argon2.
- Untuk lomba: file JS statis selalu jadi target pertama — cek
  `view-source:` dan un-minify sebelum brute force.
