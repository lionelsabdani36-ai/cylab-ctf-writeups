# Writeup: Hidden in plainsight (Challenge ID: 524)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Steganography & JPEG Metadata
- **Difficulty:** Easy
- **Author:** Yahaya Meddy
- **Event:** picoMini by CMU-Africa
- **Points:** 100
- **Flag:** `academy{h1dd3n_1n_1m4g3_d0c4a4e2}`

---

## Deskripsi Tantangan
> You’re given a seemingly ordinary JPG image. Something is tucked away out of sight inside the file. Your task is to discover the hidden payload and extract the flag.
> Download the jpg image `img.jpg`.
> Hints:
> 1. Download the jpg image and read its metadata.

---

## Analisis Kerentanan & Konsep Teknis
Tantangan ini menggabungkan dua teknik steganografi:
1. **Metadata Header Comment:** Pemeriksaan penanda JPEG `COM` (`0xFFFE`) mengungkap komentar teks yang dienkode dalam format Base64:
   ```text
   c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9
   ```
   Setelah didekode menghasilkan:
   ```text
   steghide:cEF6endvcmQ=
   ```
2. **Kunci Sandi Ekstraksi (Steghide Passphrase):**
   String Base64 kedua `cEF6endvcmQ=` didekode menjadi teks biasa:
   ```text
   pAzzword
   ```
3. **Steganografi DCT/Steghide:**
   Alat `steghide` menyematkan berkas rahasia (`flag.txt`) ke dalam koefisien Discrete Cosine Transform (DCT) gambar JPEG dengan proteksi enkripsi berbasis kata sandi `pAzzword`.

---

## Tahapan Eksploitasi & Solusi
1. Periksa segmen komentar JPEG:
   ```bash
   file img.jpg
   # img.jpg: JPEG image data, ..., comment: "c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9"
   ```
2. Dapatkan passphrase:
   ```bash
   echo "c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9" | base64 -d
   # steghide:cEF6endvcmQ=
   echo "cEF6endvcmQ=" | base64 -d
   # pAzzword
   ```
3. Ekstraksi data menggunakan `steghide`:
   ```bash
   steghide extract -sf img.jpg -p pAzzword
   cat flag.txt
   ```
4. Output flag:
   ```text
   academy{h1dd3n_1n_1m4g3_d0c4a4e2}
   ```

---

## Pembelajaran Defensif & Mitigasi LKS
- **Pendeteksian Saluran Tersembunyi (Covert Channels):** Berkas media yang diunggah ke portal web publik sering dimanfaatkan penyerang untuk C2 komunikasi atau exfiltration data rahasia.
- **Normalisasi dan Rekompresi Media:** CMS dan gateway berkas harus melakukan re-encoding/stripping metadata pada gambar yang diunggah pengguna untuk menghancurkan payload steganografi.
