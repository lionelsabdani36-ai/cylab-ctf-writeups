# Writeup: waves over lambda (Challenge ID: 38)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Classical Substitution
- **Difficulty:** Medium
- **Author:** invisibility/Danny
- **Event:** picoCTF 2019
- **Points:** 300
- **Flag:** `frequency_is_c_over_lambda_vddcgoslot` (mentah, tanpa pembungkus)

---

## Problem Statement & Scope
Layanan netcat mengirim teks terenkripsi substitusi monoalfabetik (±1400–1680 karakter, huruf kecil + underscore). Tugas: dekripsi dan kirim kembali plaintext untuk mendapatkan flag. Flag adalah segmen terakhir plaintext.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Substitusi monoalfabetik** mempertahankan distribusi frekuensi huruf; dengan ciphertext cukup panjang, serangan crib + hill-climbing berbasis kamus konvergen ke kunci penuh.
2. **Crib judul:** ciphertext selalu diawali segmen yang terdecode menjadi kalimat `congrats here is your flag - frequency_is_c_over_lambda_...`; crib ini mem-bootstrap kunci awal.
3. **Format flag non-standar:** varian `academy{...}`, `picoCTF{...}`, `flag{...}` semuanya ditolak (`correct: false`); flag yang diterima adalah string mentah `frequency_is_c_over_lambda_vddcgoslot`. Selalu uji varian format saat submit gagal.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Provision instance, hubungkan socket, simpan ciphertext ke file.
2. Bangun solver substitusi: inisialisasi kunci dari crib judul, lalu iterasi hill-climbing dengan wordlist (370.105 kata bahasa Inggris) hingga skor kata-valid maksimal.
3. Kunci konvergen; decode penuh memberi `congrats here is your flag - frequency_is_c_over_lambda_vddcgoslot`.
4. Verifikasi dengan 2 koneksi independen (ciphertext baru, segmen akhir plaintext identik).
5. Submit string mentah → `correct: true`.

---

## Flag & Verifikasi
- **Flag:** `frequency_is_c_over_lambda_vddcgoslot`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201). Catatan: tiga varian berpembungkus kurung kurawal ditolak sebelum versi mentah diterima.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Jangan memakai substitusi klasik** untuk data sensitif; gunakan cipher modern (AES-GCM) dengan kunci acak.
- **Crib attack:** setiap struktur yang dapat diprediksi (header, judul, format flag) adalah titik masuk kriptanalisis.
- **Validasi format flag:** catat flag native bila berbeda dari format komunitas `CTF{...}`.

---

## Solver
Lihat `scripts/solve_38_waves_over_lambda.py` — konek ke layanan, memecahkan substitusi dengan kunci yang di-crack, dan mencetak flag.
