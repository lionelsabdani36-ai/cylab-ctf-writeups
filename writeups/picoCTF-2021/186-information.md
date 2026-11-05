# Writeup: information (Challenge ID: 186)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Image Metadata Extraction & Base64 Carving
- **Difficulty:** Easy (diff=1)
- **Author:** Susan Culkin
- **Event:** picoCTF 2021
- **Points:** 10
- **Flag:** `academy{the_m3tadata_1s_modified}`

---

## Problem Statement & Scope

Diberikan sebuah berkas gambar digital berformat JPEG bernama `cat.jpg` yang dapat diunduh dari pustaka berkas CyLab Academy. Deskripsi soal menyatakan: *"Files can always be changed in a secret way. Can you find the flag?"*.

Skenario ini mensimulasikan teknik transmisi data rahasia (*covert storage channel*) atau penyembunyian artefak bukti digital dalam investigasi forensik, di mana informasi sensitif disisipkan ke dalam atribut metadata gambar tanpa merusak integritas visual berkas.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Metadata Berkas Digital (EXIF, IPTC, XMP):**
   - Berkas media (JPEG, TIFF, PDF) mendukung standar penyimpanan metadata seperti *Exchangeable Image File Format* (EXIF) dan *Extensible Metadata Platform* (XMP).
   - Segmen APP1 (`0xFFE1`) pada struktur JPEG JFIF secara default digunakan oleh pemroses citra untuk menyimpan informasi kamera, lisensi hak cipta, dan deskripsi dokumen dalam format XML/RDF terstruktur.
2. **Exposure of Sensitive Information (CWE-200 / NIST SP 800-115):**
   - Banyak sistem dan pengguna gagal melakukan *metadata sanitization* (pembersihan metadata) sebelum mempublikasikan berkas ke domain publik.
   - Pada berkas `cat.jpg`, penyerang menyisipkan string berkode Base64 pada atribut XMP `License`:
     `License: YWNhZGVteXt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9`
   - Pola Base64 mudah diidentifikasi karena memiliki set karakter alfanumerik `[A-Za-z0-9+/]` dengan panjang modulo 4 dan padding `=`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Metadata Berkas:**
   Gunakan utilitas forensik `exiftool` untuk membaca seluruh segmen metadata berkas gambar:
   ```bash
   exiftool cat.jpg
   ```
   Atau inspeksi segmen teks XMP menggunakan perintah Linux standar:
   ```bash
   strings cat.jpg | grep -i "license"
   ```
2. **Identifikasi String Tersandi:**
   Hasil ekstraksi menampilkan field `License` yang berisi string tersandi:
   ```text
   License : YWNhZGVteXt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9
   ```
3. **Penerjemahan Payload Base64:**
   Lakukan decoding Base64 langsung melalui shell:
   ```bash
   echo "YWNhZGVteXt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9" | base64 -d
   ```
   Output langsung menghasilkan flag:
   ```text
   academy{the_m3tadata_1s_modified}
   ```

---

## Flag & Verifikasi

- **Flag:** `academy{the_m3tadata_1s_modified}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true, "user": 1072359, "challenge": 186}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Metadata Scrubbing / Sanitization:** Pada modul *Incident Response & Defensive Hardening* LKS Cyber Security, berkas publik harus melalui pipeline sanitasi metadata (misalnya menggunakan `exiftool -all= <file>` atau library pemroses gambar yang mengabaikan segmen APP1/XMP) untuk mencegah kebocoran informasi internal (*data leakage* / CWE-200).
- **Inspeksi Forensik Berkas Masuk:** Tim analis SOC/CSIRT wajib memeriksa integritas metadata berkas yang diunggah ke portal web untuk mendeteksi potensi *covert storage channel*, steganografi, atau muatan C2 yang diselipkan dalam gambar.

---

## Solver

Lihat `scripts/solve_186_information.py` — script otomasi mandiri untuk ekstraksi dan dekoding metadata gambar secara programatik.
