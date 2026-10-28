# Writeup: Pixelated (Challenge ID: 100)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Visual Cryptography
- **Difficulty:** Easy
- **Author:** Sara
- **Event:** picoCTF 2021
- **Points:** 200
- **Flag:** `academy{2f16d0c4}`

---

## Problem Statement & Scope
Diberikan dua gambar `scrambled1.png` dan `scrambled2.png` (256x256 RGB). Petunjuk mengarah ke *visual cryptography* dan berbagai cara "menumpuk" gambar.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Visual Cryptography (Naor–Shamir):** Rahasia dibagi menjadi share acak; menumpuk share (OR/AND logis) merekonstruksi citra.
2. **Share Komplementer:** Di sini kedua share hampir berkorelasi negatif sempurna (korelasi piksel -0.9864; 192.060 dari 196.608 kanal memenuhi `p1+p2=255`). Piksel teks adalah 1.516 piksel yang *menyimpang* dari komplemen — mengisolasi penyimpangan tersebut merekonstruksi flag sebagai piksel putih di atas hitam.
3. **Anti-OCR Noise:** Teks dibentuk dari titik warna acak sehingga OCR naif gagal, tetapi maska statistik tetap deterministik.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh kedua PNG, decode manual (zlib + unfilter scanline PNG).
2. Untuk tiap piksel, hitung deviasi `|p1+p2-255|` per kanal; hanya 1.516 piksel yang non-komplementer (bbox x 26–228, y 54–75).
3. Render piksel menyimpang sebagai putih di atas hitam, crop + upscale 6x.
4. Baca flag: `academy{2f16d0c4}` (JANGAN menebak varian visual — tiga pembacaan visual memberi `...d00c4`/`...800c4` yang semuanya ditolak; maska deviasi memberi `...d0c4` yang diterima).

---

## Flag & Verifikasi
- **Flag:** `academy{2f16d0c4}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Jangan Andalkan Obfuskasi Visual:** Noise warna tidak menggantikan enkripsi; analisis statistik selalu bisa mengekstrak sinyal.
- **Secret Sharing Sejati:** Gunakan skema ambang kriptografis (Shamir Secret Sharing) dengan share yang information-theoretic secure, bukan komplemen piksel.

---

## Solver
Lihat `scripts/solve_100_pixelated.py` — merekonstruksi flag dari maska non-komplementer kedua share.
