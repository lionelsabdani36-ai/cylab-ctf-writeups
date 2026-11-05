# Writeup: Enhance! (Challenge ID: 265)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Vector Graphics & XML Structure Analysis
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{3nh4nc3d_001f8059}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman forensik berkas grafik vektor Scalable Vector Graphics (SVG):
> *"Download this image file and find the flag."*
> Artefak: `drawing.flag.svg`

Peserta diberikan sebuah berkas citra berformat SVG. Saat dibuka menggunakan penampil citra biasa atau peramban web (*browser*), citra menampilkan ilustrasi grafis lingkaran bertingkat dengan teks yang terdistorsi atau tersembunyi pada tingkat perbesaran (*zoom*) tertentu, mengarahkan pada manipulasi struktur internal XML.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Berkas Scalable Vector Graphics (W3C Recommendation):**
   - Berbeda dengan citra raster berbasis kisi piksel (seperti PNG, JPEG, BMP), berkas SVG disimpan dalam bentuk teks berbasis format XML (*Extensible Markup Language*).
   - Seluruh elemen bentuk, garis kurva, dan teks didefinisikan sebagai tag markup (`<path>`, `<circle>`, `<text>`, `<tspan>`).
   - Sifat berbasis teks ini memungkinkan data teks tersembunyi disematkan secara langsung di dalam elemen markup tanpa perlu modul steganografi raster khusus.

2. **Manipulasi Elemen Teks dan Fragmen `<tspan>`:**
   - Tag `<text>` pada SVG mendukung sub-elemen `<tspan>` untuk mengatur format tipografi parsial, pergeseran posisi koordinat ($x, y$), dan *kerning*.
   - Dalam studi kasus ini, flag tidak ditulis dalam satu string bersambung tunggal, melainkan dipecah menjadi fragmen-fragmen karakter di dalam beberapa elemen `<tspan>` terpisah yang diselingi spasi dan baris baru:
     ```xml
     <tspan ...>a </tspan>
     <tspan ...>c </tspan>
     <tspan ...>a </tspan>
     ...
     <tspan ...>y { 3 n h 4 n </tspan>
     <tspan ...>c 3 d _ 0 0 1 f 8 0 5 9 }</tspan>
     ```
   - Koordinat tampilan grafis diatur sedemikian rupa sehingga rendering visual tampak tidak utuh atau terdistorsi kecuali pengguna melakukan "enhancement" (pembacaan kode sumber langsung atau perbesaran mendalam).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak Berkas:**
   Unduh artefak SVG dari CDN resmi:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/248587d9a868db74a285623697f78ef3d87561aaa16ff1fb211fe88cd72f4a6c/drawing.flag.svg
   ```

2. **Inspeksi Struktur Berkas (Triage Forensik):**
   Periksa tipe berkas menggunakan utilitas `file`:
   ```bash
   file drawing.flag.svg
   ```
   Keluaran:
   ```text
   drawing.flag.svg: SVG Scalable Vector Graphics image
   ```

3. **Pencarian String & Parsing Struktur XML:**
   Karena berkas SVG merupakan teks XML murni, lakukan ekstraksi seluruh teks di dalam tag `<tspan>` menggunakan ekspresi reguler atau parser XML:
   ```bash
   grep -oP '(?<=<tspan)[^>]*>[^<]*' drawing.flag.svg
   ```
   Fragmen teks yang ditemukan:
   ```text
   >a 
   >c 
   >a 
   >d 
   >e 
   >m 
   >y { 3 n h 4 n 
   >c 3 d _ 0 0 1 f 8 0 5 9 }
   ```

4. **Rekonstruksi Token Flag:**
   Gabungkan seluruh fragmen dan bersihkan karakter spasi serta *newline*:
   ```python
   import re
   raw = open("drawing.flag.svg").read()
   tspans = re.findall(r'<tspan[^>]*>(.*?)</tspan>', raw)
   flag = "".join(t.strip() for t in tspans).replace(" ", "")
   print(flag)
   # Hasil: academy{3nh4nc3d_001f8059}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{3nh4nc3d_001f8059}`
- **Verifikasi API Platform:** Validasi token melalui endpoint `POST /api/submissions/` menghasilkan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 265, "flag": "academy{3nh4nc3d_001f8059}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Dalam kompetisi forensik LKS, peserta harus mengenali perbedaan mendasar antara citra raster dan vektor. Jangan terburu-buru menggunakan tool steganografi piksel (`zsteg`, `steghide`) pada berkas SVG. Lakukan *file identification* terlebih dahulu dan manfaatkan analisis teks/XML.
- **Mitigasi Defensif (Pencegahan Kebocoran Informasi pada Artefak Grafis):**
  1. *Sanitasi Metadata dan Elemen Grafis Tersembunyi (SVG Stripping):* Sebelum memublikasikan diagram atau grafis vektor korporat ke publik, jalankan utilitas pembersih SVG (seperti `svgo` / SVG Optimizer) untuk menghapus layer tersembunyi, teks komentar, metadata editor (Inkscape/Illustrator), dan tag `<tspan>` yang tidak terlihat.
  2. *Data Loss Prevention (DLP) untuk Format Berbasis Vektor:* Sistem pemantau kebocoran data wajib memindai konten internal berkas dokumen berbasis teks/XML (SVG, DOCX, XLSX, PDF) terhadap pola ekspresi reguler rahasia (kredensial, kunci API, NIK) sebelum keluar dari perimeter jaringan internal.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_265_enhance.py`.
