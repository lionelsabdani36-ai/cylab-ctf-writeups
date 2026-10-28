# Writeup: Matryoshka doll (Challenge ID: 129)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / File Carving
- **Difficulty:** Easy
- **Author:** Susie/Pandu
- **Event:** picoCTF 2021
- **Points:** 100
- **Flag:** `academy{ZNTyvSDXRNO1d0xCkBRMhAoiafpCTvgW}`

---

## Problem Statement & Scope
Diberikan berkas `dolls.jpg` (ekstensi JPG, isi aktual PNG 594×1104). Seperti boneka Matryoshka, di dalamnya tersembunyi lapisan berkas bertingkat. Tugas: kupas seluruh lapisan hingga flag ditemukan.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Struktur PNG:** Berkas PNG adalah deretan *chunk* (`IHDR … IDAT … IEND`). Data apa pun yang menempel **setelah chunk `IEND`** diabaikan penampil gambar tetapi tetap menjadi bagian berkas — lokasi klasik penyembunyian data.
2. **Tanda Tangan ZIP:** Arsip ZIP diawali magic bytes `PK\x03\x04`. Pencarian biner (*carving*) terhadap pola ini di dalam berkas pembawa mengungkap lampiran tersembunyi tanpa perkakas khusus.
3. **Rekursi:** Setiap lapisan hasil ekstraksi adalah gambar PNG lain yang juga ditempeli ZIP — pola berulang hingga lapisan inti berisi flag.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh dan periksa tipe asli:
   ```bash
   curl -sL -O https://challenge-files.cylabacademy.net/library/a268db7b2edb5615a738f69c2c79faa4d8a6bcde6b0c2f2f797a8f319cb52fe2a5/dolls.jpg
   file dolls.jpg   # PNG image data, 594 x 1104
   ```
2. Urai chunk PNG: deretan `IHDR … IDAT … IEND` berakhir di offset 272480, dan tepat setelahnya (offset 272492) terdapat header `PK\x03\x04`.
3. Potong biner dari offset 272492 dan buka sebagai ZIP → berisi `base_images/2_c.jpg`.
4. Ulangi carving pada tiap lapisan:
   - `2_c.jpg` → ZIP di offset 187707 → `base_images/3_c.jpg`
   - `3_c.jpg` → ZIP di offset 123606 → `base_images/4_c.jpg`
   - `4_c.jpg` → berisi teks flag langsung: `academy{ZNTyvSDXRNO1d0xCkBRMhAoiafpCTvgW}`.
5. Seluruh proses diotomatiskan dalam solver (loop carving maksimal 12 lapis).

---

## Flag & Verifikasi
- **Flag:** `academy{ZNTyvSDXRNO1d0xCkBRMhAoiafpCTvgW}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Jangan Percaya Ekstensi:** Selalu identifikasi tipe berkas via magic bytes (`file`, header heksadesimal), bukan nama.
- **Alur Forensik Standar:** Ukuran janggal → parse struktur → cari magic bytes tertanam → carving → rekursi. Kuasai pola ini untuk semua tantangan "doll"/stego.
- **Mitigasi:** Data sensitif tidak boleh disisipkan ke berkas media yang didistribusikan publik. Terapkan *data loss prevention* dan audit artefak rilis agar tidak ada lampiran tersembunyi.
