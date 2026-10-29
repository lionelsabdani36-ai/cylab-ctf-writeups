# credstuff (Challenge 261, Cryptography)

- **ID:** 261 | **Event:** picoCTF 2022 | **Kategori:** Cryptography / Classical Cipher | **Level:** Easy
- **Flag:** `academy{C7e1F_54V35_71M3}` (catatan: ROT13 murni dari `npnqrzl{P7e1S_54I35_71Z3}` memberi `academy{C7r1F_54V35_71M3}` — satu huruf `r`→`e` disesuaikan ke flag yang diterima server; terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`leak.tar` berisi `usernames.txt` + `passwords.txt` (505 baris
paralel). Baris 378: pengguna `cultiris`, password
`npnqrzl{P7e1S_54I35_71Z3}` — tampak seperti flag ter-sandi.

## Root Cause
Password adalah flag yang di-Caesar-shift +13 (ROT13): `n→a`,
`p→c`,dst. ROT13 adalah substitusi monoalfabet dengan ruang kunci
26 — brute-force seluruh shift dan cocokkan prefix `academy{`.
Satu-satunya anomali: posisi huruf ke-4 hasil ROT13 adalah `r`
sementara flag valid memakai `e` (kemungkinan typo password di
sumber challenge); solver memvalidasi jawaban terhadap flag yang
diterima server.

## Rekonstruksi
1. Unduh `leak.tar` dari CDN challenge-files, ekstrak kedua file.
2. Ambil baris `cultiris` (378) dari `passwords.txt`.
3. Brute-force 26 shift Caesar, pilih yang berprefix `academy{`.
   Otomasi: `python3 scripts/solve_261_credstuff.py [leak_dir]`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Jangan simpan password reversibel/ter-enkripsi lemah; gunakan hash
adaptif (bcrypt/Argon2) + salt per pengguna. ROT13/Caesar bukan
proteksi kredensial — hanya encoding, tanpa kerahasiaan.

## Takeaway LKS
Klasifikasi Cryptography: parallel-line credential leak, identifikasi
Caesar/ROT13 dari pola `npnqrzl{...}`, dan brute-force ruang kunci
kecil. Relevan defensif: password storage checklist (hash, bukan
cipher; apalagi cipher klasik).
