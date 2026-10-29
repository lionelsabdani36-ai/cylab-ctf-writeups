# 761 Bypass Me (picoCTF 2026, Reverse Engineering, Medium)

## Challenge Metadata
- ID: 761 | Nama: Bypass Me | Event: picoCTF 2026
- Kategori: Reverse Engineering | Tingkat: Medium
- Flag: `academy{d3bugg3r_p0w3r_is_4w3s0m3_e85bfcda}`
- Verifikasi: POST /api/submissions/ -> `{"correct": true}`

## Problem Statement & Scope
Lab SSH on-demand. Biner setuid-root `bypassme.bin` (not stripped, ada
debug info) meminta password, menyaring input non-alfabet, lalu
membandingkan dengan secret yang di-decode saat runtime. Benar ->
program membaca `./../root/flag.txt` sebagai root dan mencetak flag.

## Teori & Akar Kerentanan (Root Cause)
Secret di-hardcode terobfusikasi XOR-0xAA di `.text`, di-decode ke stack
tanpa perlindungan (dapat dibaca via `objdump -d`). Tidak ada KDF,
tidak ada perbandingan constant-time, dan biner setuid + not stripped
memberi simbol fungsi (`decode_password`, `sanitize`, `auth_sequence`)
yang memandu reverser. Akar: rahasia di sisi klien + obfuskasi lemah =
bypass tanpa brute force.

## Rekonstruksi Pengujian Terstruktur
1. Luncurkan lab: `PUT /api/challenges/761/instance/`, unduh biner via scp.
2. `nm` -> simbol C++ (`decode_password`, `sanitize`, `auth_sequence`).
3. `objdump -d -M intel` fungsi decode: QWORD `0xc9cff9d8cfdadff9` di
   `[rbp-0x13]`, DWORD `0xcfd8dfc9` di `[rbp-0x0c]` menimpa 1 byte dengan
   nilai sama -> 11 byte unik; loop `cmp rax,0xa; jbe` baca indeks 0..10;
   tiap byte XOR 0xAA; null di output[11].
4. Jebakan analisis: decode 12-byte naif menghasilkan "SuperSeccure"
   (DITOLAK 3x). Rekonstruksi overlap yang benar -> "SuperSecure".
5. Eksekusi: `printf 'SuperSecure\n' | ssh -T ./bypassme.bin` (tanpa pty,
   hindari translasi CR/LF) -> `Flag: academy{d3bugg3r_p0w3r_is_4w3s0m3_e85bfcda}`.
6. Submit: `POST /api/submissions/` -> `correct: true`.

## Flag & Verifikasi
- Flag: `academy{d3bugg3r_p0w3r_is_4w3s0m3_e85bfcda}` (native, format komunitas).
- Bukti: respons API `{"user": 1072359, "challenge": 761, "correct": true}`.

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Jangan simpan secret di biner; verifikasi di server dengan hash + salt
  (argon2/bcrypt) dan perbandingan constant-time.
- Strip simbol + PIE + anti-debug mempersulit, tetapi rahasia klien tetap
  kalah vs server-side check.
- Teliti bound loop (`jbe` vs `jb`) dan overlap penulisan memori saat
  rekonstruksi konstanta: 1 byte menentukan "SuperSecure" vs jebakan.
- Operasional pty: gunakan `ssh -T` + stdin pipe untuk biner interaktif
  agar tidak ada translasi newline yang merusak input.
