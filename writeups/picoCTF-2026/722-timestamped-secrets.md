# Timestamped Secrets (Challenge 722, Cryptography)

- **ID:** 722 | **Event:** picoCTF 2026 | **Kategori:** Cryptography | **Level:** Medium
- **Flag:** `academy{sa3S_sEc9t_3b464909}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`encryption.py`: AES-128-ECB dengan kunci `sha256(str(unix_timestamp)).digest()[:16]`.
Pesan challenge membocorkan waktu enkripsi (~1790147519 UTC) — ruang kunci
bukan 2^128 melainkan jendela timestamp sempit. Brute-force timestamp di
sekitar hint, coba dekripsi AES-ECB + unpad PKCS7, terima yang ASCII/flag.

## Root Cause
Kunci diturunkan dari timestamp yang dapat ditebak (low-entropy KDF input)
dan waktu enkripsi dibocorkan ke penyerang. Pencarian ±60 hari = ~5 juta
kandidat — sepele. Pelajaran: kunci harus dari CSPRNG, bukan waktu;
jangan bocorkan parameter KDF.

## Rekonstruksi
1. Parse hint timestamp + ciphertext hex dari `message.txt`.
2. Untuk tiap `ts` di jendela: `key = sha256(str(ts))[:16]`,
   `unpad(AES_ECB_decrypt(ct))`, cek `academy{`.
3. `ts = 1790147519` → `academy{sa3S_sEc9t_3b464909}`.
   Otomasi: `python3 scripts/solve_722_timestamped_secrets.py message.txt`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Kunci AES dari `secrets.token_bytes(16)`; jika butuh KDF pakai
HKDF/scrypt dengan salt acak; tambah autentikasi (GCM, bukan ECB).

## Takeaway LKS
Klasifikasi Cryptography: serangan ruang-kunci kecil + ECB deterministik.
Pola "kunci dari data tebak" (waktu/PID/rand lemah) — langkah pertama
saat melihat KDF aneh: ukur entropi inputnya.
