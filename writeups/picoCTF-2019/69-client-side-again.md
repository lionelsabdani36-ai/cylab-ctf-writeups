# Writeup: Client-side-again (Challenge ID: 69)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Client-Side Validation
- **Difficulty:** Medium
- **Author:** Danny
- **Event:** picoCTF 2019
- **Points:** 200
- **Flag:** `academy{not_this_again_3b977f}`

---

## Problem Statement & Scope
Portal login "Secure Login Portal V2.0" yang memvalidasi password sepenuhnya di browser (JavaScript ter-obfusikasi), memakai array string terotasi dan pemeriksaan `substring` per segmen.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Validasi client-side tidak pernah aman:** seluruh logika dan konstanta pembanding dikirim ke browser; analis cukup membaca JS untuk merekonstruksi password.
2. **De-obfusikasi array:** skrip memutar array string 435 kali (`while(--0x1b4)`); `435 mod 10 = 5` sehingga tabel akhir adalah rotasi kiri 5 dari tabel awal — petakan setiap `_0x4b5b('0xN')` ke string aslinya.
3. **Rekonstruksi per segmen** (split=4): `substring(0,8)=='academy{'`, `(3,6)=='dem'`, `(6,11)=='y{not'`, `(7,9)=='{n'`, `(8,16)=='not_this'`, `(12,16)=='this'`, `(16,24)=='_again_3'`, `(24,32)=='b977f}'` — semua konsisten membentuk satu string 30 karakter.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Provision instance, unduh halaman login, rapikan JS ter-obfusikasi.
2. Hitung rotasi array (435 shift → offset 5), petakan indeks `0x0`–`0x9`.
3. Rakit segmen: `academy{` + `not_this` + `_again_3` + `b977f}` = `academy{not_this_again_3b977f}` (30 char).
4. Verifikasi tiap syarat substring terpenuhi, submit sebagai flag.

---

## Flag & Verifikasi
- **Flag:** `academy{not_this_again_3b977f}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Autentikasi wajib server-side:** jangan pernah menaruh secret/pembanding kredensial di JavaScript.
- **Obfuskasi ≠ enkripsi:** rotasi array dan nama variabel heks tidak menghentikan analis; gunakan hashing + salt di server (bcrypt/argon2).
- Teknik de-obfusikasi array-rotasi ini berguna untuk analisis malware JS di modul Defensive.

---

## Solver
Lihat `scripts/solve_69_client_side_again.py` — mengambil halaman login, mende-obfusikasi tabel string, dan merekonstruksi password.
