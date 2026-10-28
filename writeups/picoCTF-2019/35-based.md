# Writeup: Based (Challenge ID: 35)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Encoding
- **Difficulty:** Medium
- **Author:** Alex Fulton/Daniel Tunitis
- **Event:** picoCTF 2019
- **Points:** 200
- **Flag:** `academy{learning_about_converting_values_Ee545DDA}`

---

## Problem Statement & Scope
Layanan netcat tiga tahap. Tiap tahap menampilkan kata yang dienkode basis berbeda dan meminta jawaban plaintext-nya: tahap 1 biner, tahap 2 oktal, tahap 3 heksadesimal. Semua tahap harus dijawab benar dalam satu sesi untuk mendapatkan flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Basis bilangan posisional:** biner (blok 8-bit per karakter), oktal (blok 3 digit per karakter), heksadesimal (2 digit hex per karakter) — semuanya merepresentasikan byte ASCII yang sama.
2. **Tokenisasi penting:** token heks tahap 3 berukuran 10 digit (5 byte, mis. `6e75727365` = "nurse"); decoder naif per-token gagal, harus digabung lalu dipecah per 2 digit (`bytes.fromhex`).
3. **Otomatisasi interaktif:** pola "jawab N ronde" paling aman diselesaikan dengan klien socket yang membaca prompt, mendeteksi basis aktif, dan menjawab — menghilangkan kesalahan salin-tempel manual.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Provision instance (`PUT /api/challenges/35/instance/`, slot harus kosong dulu, tunggu hingga `RUNNING`), baca endpoint `nc` dari deskripsi.
2. Tahap 1: pecah string biner per 8 bit → `chr(int(b, 2))`.
3. Tahap 2: pecah string oktal per 3 digit → `chr(int(o, 8))`.
4. Tahap 3: gabung semua digit heks, pecah per 2 digit → `bytes.fromhex(...).decode()`.
5. Server mengembalikan flag setelah tiga jawaban benar.

---

## Flag & Verifikasi
- **Flag:** `academy{learning_about_converting_values_Ee545DDA}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Kenali encoding dari alfabetnya:** alfabet `{0,1}` = biner, `{0-7}` = oktal, `{0-9a-f}` = heks — identifikasi basis dalam hitungan detik.
- **Pecah token multi-byte dengan benar:** token heks tidak selalu 2 digit; normalisasi dulu (gabung lalu potong per 2) sebelum decode.
- **Mitigasi:** challenge edukasi semacam ini memang tidak perlu "ditambal" — tujuannya melatih literasi encoding; di sistem nyata, jangan mengandalkan encoding sebagai keamanan (obscurity).

---

## Solver
Lihat `scripts/solve_35_based.py` — klien socket otomatis untuk tiga tahap konversi basis.
