# patchme.py (Challenge 287, Reverse Engineering)

- **ID:** 287 | **Event:** picoCTF 2022 | **Kategori:** Reverse Engineering | **Level:** Easy (diff 2, 100 pts)
- **Flag:** `academy{p47ch1ng_l1f3_h4ck_a68602e7}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
Program `patchme.flag.py` dijalankan di direktori yang sama dengan `flag.txt.enc`.
Fungsi `str_xor()` mendekripsi flag dengan kunci `"utilitarian"`, tetapi hanya
berjalan setelah `level_1_pw_check()` lolos.

## Root Cause
Password ditulis terang di dalam kode sebagai 4 literal yang digabung dengan
backslash-continuation:
`user_pw == "ak98" + "-=90" + "adfjhgj321" + "sleuth9000"`.
Tidak ada hashing, tidak ada proteksi — kredensial = dokumentasi.

## Rekonstruksi
1. Unduh `patchme.flag.py` + `flag.txt.enc` dari CDN challenge-files
   (URL ada di `GET /api/challenges/287/instance/` -> `description`).
2. Baca password dari source: `ak98-=90adfjhgj321sleuth9000`.
3. Terapkan XOR kunci-berulang `"utilitarian"` ke `flag.txt.enc`.
   Otomasi: `python3 scripts/solve_287_patchme.py <dir-file>`.

## Mitigasi
Jangan simpan secret di source; verifikasi password dengan hash garam
(Argon2/bcrypt) di sisi server, dan jangan kirim logika cek ke klien.

## Takeaway LKS
Reverse dasar: baca source sebelum brute-force; kenali pola XOR
kunci-berulang dan dekripsi offline tanpa menjalankan program target.
