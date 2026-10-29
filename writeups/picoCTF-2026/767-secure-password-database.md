# Secure Password Database (Challenge 767, Reverse Engineering)

- **ID:** 767 | **Event:** picoCTF 2026 | **Kategori:** Reverse Engineering / Binary Exploitation | **Level:** Medium
- **Flag:** `academy{d0nt_trust_us3rs}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
Biner `system.out` (ELF 64-bit, not stripped) mensimulasikan database
password: minta password, minta panjang (`atoi`), cetak "stored password"
sebagai `%d` per byte, lalu minta hash (`strtoul`) dan bandingkan dengan
`make_secret()`. Cocok → cetak `flag.txt`. Lab on-demand
`xebec.cylabacademy.net:41072`.

## Root Cause
Tiga cacat berantai: (1) `strcpy` dari buffer stack 0x32 byte ke heap
`calloc(1, 0x5a)` tanpa batas — klasik heap overflow; (2) panjang dari
`atoi()` dipercaya sebagai bound loop cetak, sehingga `length=89` membaca
melewati input ke byte turunan `obf_bytes` (info leak ala heartbleed);
(3) "hash" adalah djb2 (`h=0x1505; h=h*33+c`, uint64) atas secret yang
justru tersimpan XOR-`0xAA` di `.rodata` — reversibel statis.
`make_secret` menyalin `obf_bytes^0xAA` (12 byte `iUbh81!j*hn!`) lalu hash
→ `15237662580160011234`. Secret + algoritma + kunci XOR semuanya ada di
biner: tidak perlu menebak password, cukup hitung ulang hash.

## Rekonstruksi
1. Unduh `system.out` dari CDN, `objdump -d`: petakan `main`,
   `make_secret`, `hash`; baca `obf_bytes` via gdb/`readelf`
   (`c3 ff c8 c2 92 9b 8b c0 80 c2 c4 8b 00`).
2. XOR `0xAA` → `iUbh81!j*hn!`; replikasi djb2 di Python →
   `15237662580160011234`. Validasi lokal: jalankan biner dengan
   `flag.txt` dummy, kirim `A / 89 / <hash>` → flag tercetak.
3. Launch lab: `PUT /api/challenges/767/instance/` → tunggu `RUNNING`.
4. Otomasi: `python3 scripts/solve_767_secure_password_database.py
   [host] [port]` — kirim `A`, `89`, hash target, parse `academy{...}`.
5. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Ganti `strcpy` dengan `strncpy`/`memcpy` ber-bound; jangan pernah
percayai `atoi` sebagai bound loop — clamp ke ukuran buffer aktual.
Jangan simpan secret ter-XOR konstan di `.rodata`; gunakan KDF
(bcrypt/argon2 + salt acak) dan bandingkan hash dalam constant-time.
Logika "tampilkan password tersimpan" tidak boleh ada di sistem nyata.

## Takeaway LKS
Klasifikasi Reverse Engineering: analisis statis (`objdump`, `readelf`,
`strings`, gdb), dekode XOR, replikasi KDF lemah (djb2), eksploitasi
info-leak via bound yang dikontrol user. Pola heartbleed + custom-hash
ini inti modul Binary/Reverse di LKS Cyber Security.
