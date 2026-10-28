# Writeup: tunn3l v1s10n (Challenge ID: 112)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Image Header Repair
- **Difficulty:** Easy (2)
- **Author:** Danny
- **Event:** picoCTF 2021
- **Points:** 40
- **Flag:** `academy{qu1t3_a_v13w_2020}`

---

## Problem Statement & Scope
Diberikan berkas `tunn3l_v1s10n` — gambar yang tidak bisa dibuka normal. Tugas: pulihkan dan baca flag yang tersembunyi sebagai teks overlay.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Header BMP Rusak:** Field ukuran DIB = `0xd0ba` (53434 — sebenarnya nilai offbits) dan tinggi 306, tetapi data piksel asli mulai di offset 54 (header 14 + DIB 40) dengan stride `((1134*3+3)//4)*4 = 3404`.
2. **Tinggi Sejati dari Ukuran:** `(2893454 - 54) / 3404 = 850` baris — gambar panorama jauh lebih tinggi dari klaim header.
3. **BMP Bottom-Up:** Baris 0 = bawah gambar; rekonstruksi BGR→RGB dengan membalik urutan baris. Teks overlay kuning-pucat di baris 0..130 adalah permainan kata "quite a view" dari foto pegunungan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh artefak:
   ```bash
   curl -sL -O https://challenge-files.cylabacademy.net/library/3b5add918cb4cf98fa62ef4e05eb8c55c6c9ae547a939c6be992ee3aa656ee69/tunn3l_v1s10n
   ```
2. Parse header: `bfSize` 2893454, offbits 53434 (salah), W=1134, H=306 (salah), bpp=24.
3. Hitung tinggi sejati 850 dari ukuran file; baca piksel dari offset 54, balik urutan baris, konversi BGR→RGB.
4. Crop pita teks (baris 0..130, 567x65) → baca overlay: `academy{qu1t3_a_v13w_2020}`.

---

## Flag & Verifikasi
- **Flag:** `academy{qu1t3_a_v13w_2020}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201); GET `/api/challenges/112/` menunjukkan `solved_by_user: true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Jangan Percaya Header:** Validasi dimensi klaim terhadap ukuran file aktual — trik klasik soal forensik gambar.
- **BMP Bottom-Up:** Selalu ingat urutan baris terbalik saat rekonstruksi manual.
- **Mitigasi:** Metadata/header yang dimanipulasi mudah dinormalisasi ulang; jangan simpan rahasia dalam berkas media publik.
