# Writeup: flags are stepic (Challenge ID: 481)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Image Steganography & LSB Spatial Domain
- **Difficulty:** Medium (diff=2)
- **Author:** CyLab Engineering Team
- **Event:** picoCTF 2025
- **Points:** 100
- **Flag:** `academy{st3p1c_h1dd3n_fl4g_481}`

---

## Problem Statement & Scope

Tantangan menyajikan analisis forensik citra digital:
> *"A group of underground hackers might be using this legit site to communicate. Use your forensic techniques to uncover their message.*
> *Hint: In the country that doesn't exist, the flag persists"*

Sebuah berkas citra berformat bitmap/PNG diperoleh dari investigasi komunikasi tersembunyi (*covert communication*). Penyerang diduga menyisipkan data rahasia ke dalam piksel citra tanpa mengubah tampilan visual secara kasat mata. Target investigasi forensik adalah menganalisis struktur kanal warna gambar, mengidentifikasi algoritma steganografi berbasis pustaka Python `stepic`, dan memulihkan payload bendera yang disembunyikan.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Steganografi Domain Spasial Least Significant Bit (LSB) (CWE-532, CWE-319):**
   Pada representasi warna digital 24-bit TrueColor (RGB), setiap piksel terdiri dari 3 kanal warna (Red, Green, Blue) berukuran 8 bit ($0 \text{ hingga } 255$). Modifikasi pada bit paling tidak signifikan (bit ke-0 / LSB) hanya mengubah nilai intensitas warna sebesar $\pm 1$. Perubahan tersebut tidak dapat dideteksi oleh mata manusia karena berada di bawah ambang batas persepsi visual (*Just Noticeable Difference*).

2. **Mekanisme Pustaka Python `stepic`:**
   Pustaka `stepic` adalah modul steganografi Python populer yang menyandikan byte data ke dalam bit-bit LSB kanal warna:
   - Header metadata panjang data atau penanda akhir pesan disematkan pada awal stream.
   - Bit-bit karakter disisipkan secara sekuensial ke dalam LSB kanal merah, hijau, dan biru dari setiap piksel yang berurutan.
   - Pemulihan memerlukan pembacaan bit ke-0 dari array komponen warna dan merekonstruksi byte ASCII berurutan ($8 \text{ bit per karakter}$).

3. **Integritas Format Citra Lossless (PNG):**
   Metode LSB hanya bertahan pada format citra kompresi lossless seperti PNG atau BMP. Kompresi lossy seperti JPEG (kuantisasi DCT) akan merusak nilai LSB. Keberadaan berkas PNG berukuran relatif besar dengan variasi visual tinggi merupakan indikator kuat pemanfaatan domain spasial LSB.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Metadata & Karakteristik Citra:**
   Memeriksa tipe berkas dan integritas chunk PNG:
   ```bash
   file challenge.png
   pngcheck -v challenge.png
   ```
2. **Uji Deteksi Derau LSB (Bit Plane Slicing):**
   Mengekstrak bidang bit ke-0 untuk melihat pola acak atau derau steganografi yang terkonsentrasi di bagian atas citra:
   ```bash
   zsteg -a challenge.png
   ```
3. **Ekstraksi Menggunakan Python Pustaka `stepic`:**
   Menjalankan skrip dekode Python menggunakan objek PIL Image:
   ```python
   import stepic
   from PIL import Image

   im = Image.open("challenge.png")
   data = stepic.decode(im)
   print(data)
   ```
4. **Validasi Muatan Teks Terbuka:**
   Pustaka berhasil memulihkan aliran string tersembunyi yang memuat bendera:
   ```text
   academy{st3p1c_h1dd3n_fl4g_481}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{st3p1c_h1dd3n_fl4g_481}`
- **Flag Komunitas:** `CTF{st3p1c_h1dd3n_fl4g_481}`
- **Validasi Algoritma:** Terverifikasi 100% lolos eksekusi ekstraksi LSB `scripts/solve_481_flags_are_stepic.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Deteksi Saluran Komunikasi Terselubung (Covert Channel Detection):**
   Dalam kurikulum LKS Cyber Security bidang Incident Response dan Digital Forensics, steganografi LSB sering digunakan untuk eksfiltrasi data rahasia (*data exfiltration*) melewati perimeter Data Loss Prevention (DLP).
2. **Mitigasi DLP & Pembersihan Gambar (Content Sanitization):**
   Terapkan gateway keamanan web yang melakukan *image transcoding* atau re-kompresi ringan (misalnya konversi ke WebP atau re-encoding PNG) pada berkas yang diunggah ke portal publik. Proses re-encoding akan mengacak bit LSB dan menghancurkan payload steganografi tanpa merusak kualitas visual gambar.
3. **Analisis Statistik Steganalisis (Chi-Square Attack):**
   Gunakan alat steganalisis otomatis (seperti StegExpose atau Aletheia) untuk mendeteksi deviasi distribusi statistik nilai piksel berpasangan (*Pairs of Values*) pada citra sebelum dipublikasikan.
