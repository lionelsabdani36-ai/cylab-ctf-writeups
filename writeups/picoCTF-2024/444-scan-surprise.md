# Writeup: Scan Surprise (Challenge ID: 444)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / QR Code Analysis
- **Difficulty:** Easy
- **Author:** Jeffery John
- **Event:** picoCTF 2024
- **Points:** 50
- **Flag:** `academy{p33k_@_b00_5f0d36e7}`

---

## Problem Statement & Scope
Peserta diberikan arsip berkas `challenge.zip` yang di dalamnya terdapat citra gambar berformat PNG (`flag.png`). Deskripsi tantangan menyebutkan bahwa flag tidak lagi diberikan dalam bentuk teks mentah melainkan tertanam di dalam gambar visual. Lingkungan pengujian mensimulasikan transmisi data berbasis visual optical machine-readable representation.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Representasi Barcode 2D (Quick Response Code):** QR Code memanfaatkan kisi modular dua dimensi dengan pola posisi persegi (finder patterns) pada tiga sudut, pola perataan (alignment patterns), dan koreksi galat Reed-Solomon (Reed-Solomon Error Correction Level L/M/Q/H).
2. **Ketiadaan Enkripsi Data Payloads:** Data muatan di dalam QR code hanya dienkode (menggunakan mode byte, numerik, atau alfanumerik), bukan dienkripsi. Siapa pun atau alat pemindai optik apa pun yang memiliki akses ke sensor kamera atau citra digital dapat merekonstruksi string teks secara langsung tanpa mekanisme otentikasi.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Ekstraksi arsip `challenge.zip` untuk mendapatkan berkas `flag.png`:
   ```bash
   unzip challenge.zip
   ```
2. Analisis citra menggunakan utilitas pemindai barcode open-source `zbarimg`:
   ```bash
   zbarimg --raw -q home/ctf-player/drop-in/flag.png
   ```
3. Alternatif menggunakan modul OpenCV / Python barcode parser (`cv2.QRCodeDetector` atau `pyzbar`):
   ```python
   import cv2
   img = cv2.imread("flag.png")
   detector = cv2.QRCodeDetector()
   val, _, _ = detector.detectAndDecode(img)
   print(val)
   ```
4. Pemindai menghasilkan token flag instan.

---

## Flag & Verifikasi
- **Flag:** `academy{p33k_@_b00_5f0d36e7}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` pada basis data CyLab Academy.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Mitigasi QRLjacking & Malicious QR:** Jangan pernah menyematkan data sensitif (API key, bearer token, kredensial) atau link dinamis tanpa verifikasi integritas ke dalam QR code publik. Penyerang kerap menempelkan stiker QR fisik palsu (quishing) di fasilitas umum untuk mengarahkan pengguna ke laman phishing.
- **Validasi Input Pemindai:** Aplikasi pembaca barcode harus selalu memvalidasi dan membatasi parser URL sebelum otomatis membuka tautan yang dihasilkan pemindai.
