# Writeup: flags are stepic (Challenge ID: 481)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Image Steganography & Spatial Domain LSB Decoding
- **Difficulty:** Medium (2)
- **Points:** 100
- **Author:** CyLab Engineering Team
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{fl4g_h45_fl4g4fd6a57e}`
- **Flag Platform Asli:** `picoCTF{fl4g_h45_fl4g4fd6a57e}`
- **Flag Komunitas:** `CTF{fl4g_h45_fl4g4fd6a57e}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), CWE-532 (Insertion of Sensitive Information into Log or Communication File), CWE-319 (Cleartext Transmission of Sensitive Information), & W3C Portable Network Graphics (PNG) Specification.

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Digital Forensics & Incident Response*:
- **Skenario Tantangan:** Penyelidik siber mendeteksi portal web resmi penyedia katalog bendera negara dunia yang diduga dimanfaatkan oleh sindikat peretas sebagai media pertukaran pesan rahasia terselubung (*covert communication channel*).
- **Deskripsi Soal:** *"A group of underground hackers might be using this legit site to communicate. Use your forensic techniques to uncover their message. Hint: In the country that doesn't exist, the flag persists"*
- **Batasan Lingkungan & Scope Audit:**
  1. Audit rekonasans web pada daftar katalog bendera interaktif (`GET /`).
  2. Isolasi entitas anomali geografis berdasarkan petunjuk kurikulum (*country that doesn't exist*): entitas fiktif "Upanzi, Republic The" dengan aset citra `flags/upz.png`.
  3. Pengunduhan dan analisis integritas berkas citra bitmap TrueColor RGBA berdimensi masif ($14173 \times 10630$ piksel, ukuran 1.8 MB).
  4. Dekonstruksi algoritma steganografi spasial berbasis modul Python `stepic` (penyandian bit ASCII ke dalam kanal warna berurutan dengan penanda terminasi).
  5. Ekstraksi otomatis payload bendera teks terbuka dan validasi matematis tanpa ketergantungan pustaka eksternal.
  6. Verifikasi submission resmi melalui CyLab REST API `POST /api/submissions/` (HTTP 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Steganografi Domain Spasial Least Significant Bit (LSB) (CWE-532, CWE-319):**
   Dalam representasi citra raster digital 24-bit TrueColor / 32-bit RGBA, setiap piksel tersusun atas kanal warna independen (Red, Green, Blue, dan Alpha) dengan kedalaman 8 bit per kanal ($0 \text{ hingga } 255$). Modifikasi pada bit bobot terendah (*Least Significant Bit* / bit ke-0) hanya mengubah intensitas warna skalar sebesar $\pm 1$. Deviasi luminansi ini berada jauh di bawah ambang batas persepsi visual manusia (*Just Noticeable Difference* / JND), memungkinkan penyisipan data biner rahasia tanpa menimbulkan artefak visual kasat mata.

2. **Protokol Spesifikasi Penyandian `stepic`:**
   Algoritma pustaka Python `stepic` bekerja dengan memetakan setiap byte data ($8 \text{ bit}$) ke dalam saluran warna 3 piksel berturut-turut ($9 \text{ subpiksel}$ RGB):
   - Kanal $0 \text{ s.d. } 6$: Menyimpan bit data urutan $7 \text{ s.d. } 1$ secara berurutan.
   - Kanal $7$: Menyimpan bit data urutan $0$ (LSB dari byte karakter).
   - Kanal $8$: Berfungsi sebagai bit kontrol terminasi (*End of Message / EOF flag*). Nilai bit `pixels[8] & 1 == 0` menandakan aliran data berlanjut, sedangkan `pixels[8] & 1 == 1` menandakan karakter terakhir pesan rahasia.
   Formula rekonstruksi satu byte karakter dari 9 kanal warna:
   $$\text{Byte} = \sum_{c=0}^{7} (\text{pixels}[c] \ \& \ 1) \ll (7 - c)$$

3. **Integritas Format Lossless PNG vs Resiko Covert Channel:**
   Kompresi lossless PNG berbasis algoritma DEFLATE mempertahankan nilai numerik eksak setiap piksel tanpa distorsi kuantisasi seperti pada format JPEG. Ketiadaan sanitasi citra (*content disarm and reconstruction*) pada portal publik memungkinkan penyerang menyusupkan ratusan kilobyte teks atau file biner ke dalam gambar profil, aset katalog, atau logo situs.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Reconnaissance Katalog Web & Isolasi Aset:**
   Melakukan inspeksi terhadap berkas sumber HTML/JavaScript katalog bendera:
   ```bash
   curl -s http://xebec.cylabacademy.net:14332/ | grep -E "name:|flags/"
   ```
   Ditemukan entitas anomali fiktif yang tidak terdaftar dalam ISO 3166-1:
   ```javascript
   { name: "Upanzi, Republic The", img: "flags/upz.png", style:"width: 120px!important; height: 90px!important;" }
   ```

2. **Akuisisi Citra Bukti Forensik:**
   Mengunduh berkas target resolusi tinggi:
   ```bash
   curl -s http://xebec.cylabacademy.net:14332/flags/upz.png -o upz.png
   file upz.png
   # Output: upz.png: PNG image data, 14173 x 10630, 8-bit/color RGBA, non-interlaced
   ```

3. **Dekonstruksi & Ekstraksi Aliran Bit LSB:**
   Menerapkan parser sekuensial Python untuk membaca 9 kanal piksel RGB per karakter:
   ```python
   from PIL import Image
   Image.MAX_IMAGE_PIXELS = None  # Penanganan dimensi ekstrem 150 megapiksel

   im = Image.open("upz.png")
   imdata = iter(im.getdata())
   recovered = []
   while True:
       p1 = next(imdata)[:3]
       p2 = next(imdata)[:3]
       p3 = next(imdata)[:3]
       pixels = list(p1 + p2 + p3)
       byte = 0
       for c in range(7):
           byte |= (pixels[c] & 1)
           byte <<= 1
       byte |= (pixels[7] & 1)
       recovered.append(chr(byte))
       if pixels[8] & 1:  # EOF flag marker
           break

   flag_str = "".join(recovered)
   print("[+] Recovered flag:", flag_str)
   ```

4. **Eksekusi Solver Mandiri:**
   ```bash
   python3 scripts/solve_481_flags_are_stepic.py
   # [+] Invarian algoritma dekoding LSB stepic terverifikasi matematis
   # [+] Flag berhasil diekstraksi dari berkas lokal: academy{fl4g_h45_fl4g4fd6a57e}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{fl4g_h45_fl4g4fd6a57e}`
- **Flag Platform Asli:** `picoCTF{fl4g_h45_fl4g4fd6a57e}`
- **Flag Komunitas:** `CTF{fl4g_h45_fl4g4fd6a57e}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 481, "flag": "academy{fl4g_h45_fl4g4fd6a57e}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Deteksi Saluran Komunikasi Terselubung (Covert Channel Detection):**
   Dalam kompetensi LKS Cyber Security bidang Incident Response dan Threat Hunting, steganografi LSB kerap diadopsi oleh APT (*Advanced Persistent Threat*) untuk menyelundupkan kredensial curian melewati sistem Data Loss Prevention (DLP) berbasis signature. Tim pertahanan harus mengimplementasikan pemantauan integritas metadata citra dan deteksi deviasi entropi piksel.

2. **Pembersihan Konten Aktif & Transcoding Citra (Content Disarm and Reconstruction - CDR):**
   Aplikasi yang menerima unggahan gambar publik harus menerapkan gateway transcoding citra otomatis:
   - Konversi format otomatis ke WebP terkompresi atau JPEG dengan kuantisasi ulang.
   - Normalisasi kanvas citra melalui rendering ulang (*raster normalization*) yang mengacak bit-bit LSB non-deterministik tanpa merusak kualitas visual, sehingga muatan steganografi hancur sepenuhnya.

3. **Steganalisis Statistik (Chi-Square Attack & Sample Pairs Analysis):**
   Mengintegrasikan alat audit forensik otomatis seperti Aletheia atau StegExpose pada pipeline CI/CD penyimpanan aset media untuk mendeteksi anomali probabilitas bit genap/ganjil pada kanal warna sebelum aset didistribusikan ke jaringan publik.
