# Writeup: What Lies Within (Challenge ID: 74)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Image LSB Steganography & Bitplane Extraction
- **Difficulty:** Medium (diff=2)
- **Author:** Julio/Danny
- **Event:** picoCTF 2019
- **Points:** 150
- **Flag:** `academy{h1d1ng_1n_th3_b1t5}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman forensik citra digital dan teknik steganografi saluran warna:
> *"There's something in the building. Can you retrieve the flag?"*
> Artefak: `buildings.png`

Peserta diberikan berkas citra berformat Portable Network Graphics (PNG) bernama `buildings.png` beresolusi 595x421 piksel. Citra secara visual menampilkan pemandangan perkotaan dengan gedung-gedung bertingkat tanpa keanehan visual yang mencolok. Peserta diarahkan untuk mengidentifikasi keberadaan muatan data tersembunyi (*hidden payload*) yang disematkan ke dalam struktur piksel berkas.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Berkas Citra Raster PNG (RFC 2083 / ISO/IEC 15948):**
   - Format PNG menggunakan kompresi *lossless* berbasis algoritma Deflate (LZ77 + Huffman coding) serta filter prediktif per scanline.
   - Karena bersifat *lossless*, nilai piksel RGB (Red, Green, Blue) yang didekodekan dari *chunk* IDAT identik 100% dengan representasi raster aslinya tanpa distorsi kuantisasi lossy seperti pada JPEG.
   - Sifat deterministik ini memungkinkan format PNG menjadi wadah ideal untuk steganografi spasial (*spatial domain steganography*).

2. **Mekanisme Steganografi Least Significant Bit (LSB):**
   - Setiap piksel pada ruang warna 24-bit TrueColor direpresentasikan oleh 3 kanal warna: Merah (8-bit), Hijau (8-bit), dan Biru (8-bit), dengan rentang nilai $[0, 255]$.
   - Bit paling signifikan (MSB / bit ke-7) membawa bobot nilai $2^7 = 128$, sedangkan bit paling tidak signifikan (LSB / bit ke-0) hanya membawa bobot nilai $2^0 = 1$.
   - Mengubah bit ke-0 dari nilai `0` ke `1` atau sebaliknya hanya mengubah intensitas warna sebesar $\pm 1/256 \approx 0.39\%$, yang sepenuhnya berada di bawah batas diskriminasi visual sistem penglihatan manusia (*Just Noticeable Difference* / JND).
   - Penyerang menyematkan aliran data biner rahasia dengan mengganti bit LSB secara berurutan:
     $$\text{Channel}' = (\text{Channel} \ \& \ \text{0xFE}) \ | \ \text{bit}_{\text{secret}}$$

3. **Prinsip Forensik Data Carving Sesuai Standar NIST SP 800-115:**
   - NIST SP 800-115 (Section 5.2: *Target Analysis and Component Assessment*) menguraikan prosedur ekstraksi artefak tersembunyi dari berkas multimedia.
   - Evaluasi terhadap distribusi frekuensi LSB (uji visual bitplane atau uji Chi-Square / PoVs) menunjukkan anomali keseragaman entropi pada bit ke-0 dari kanal RGB, yang menandakan keberadaan payload terstruktur.
   - Kerentanan mendasar diklasifikasikan sebagai CWE-200 (*Exposure of Sensitive Information to an Unauthorized Actor*) akibat ketiadaan enkripsi lapis kedua pada muatan yang disembunyikan.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak Berkas:**
   Unduh citra resmi dari repositori aset tantangan:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/5235bfccd8f3cc2d059ee828f774846542f28f7ec66cb4f0c6ceb536c38026d4/buildings.png
   ```

2. **Identifikasi Format Berkas & Analisis Integritas Metadata:**
   Periksa header dan struktur *chunks* PNG menggunakan `file` dan `pngcheck`:
   ```bash
   file buildings.png
   # buildings.png: PNG image data, 595 x 421, 8-bit/color RGB, non-interlaced
   ```
   Analisis metadata EXIF via `exiftool` tidak menunjukkan komentar atau anotasi teks mencurigakan, mengindikasikan payload berada pada ranah spasial piksel.

3. **Ekstraksi Muatan LSB Menggunakan Perkakas Steganografi:**
   Gunakan perkakas analisis bitplane seperti `zsteg` (atau skrip Python otomasi mandiri):
   ```bash
   zsteg -a buildings.png | grep -E "academy\{|picoCTF\{"
   ```
   Keluaran:
   ```text
   b1,rgb,lsb,xy       .. text: "academy{h1d1ng_1n_th3_b1t5}"
   ```
   Modus encoding yang digunakan adalah `b1,rgb,lsb,xy`:
   - `b1`: 1 bit per kanal warna.
   - `rgb`: Ekstraksi berurutan dari kanal Merah, lalu Hijau, lalu Biru.
   - `lsb`: Mengambil bit paling rendah (Least Significant Bit).
   - `xy`: Urutan traversal piksel raster horizontal dari baris teratas ke terbawah ($y=0 \dots h-1, x=0 \dots w-1$).

4. **Ekstraksi Mandiri Melalui Skrip Python:**
   Skrip mandiri membaca citra menggunakan modul `PIL` / `Pillow`, mengiterasi setiap piksel, mengekstrak bit LSB, dan menyusunnya kembali menjadi karakter byte 8-bit:
   ```bash
   python3 scripts/solve_74_what_lies_within.py
   ```
   Keluaran:
   ```text
   [+] Recovered Flag: academy{h1d1ng_1n_th3_b1t5}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{h1d1ng_1n_th3_b1t5}`
- **Bukti Validasi REST API CyLab:** Endpoint `POST /api/submissions/` merespons dengan HTTP Status 201 Created:
  ```json
  {
    "user": 1072359,
    "challenge": 74,
    "flag": "academy{h1d1ng_1n_th3_b1t5}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Penerapan pada Modul Digital Forensics LKS:**
   - Dalam kompetisi LKS Cyber Security, modul analisis steganografi citra menuntut pemahaman mendalam tentang tata letak data bitplane, pola interleaving antar kanal warna (`RGB`, `BGR`, `RGBA`), dan perbedaan domain spasial versus transformasi frekuensi (*Discrete Cosine Transform* / DCT).
   - Peserta harus terbiasa mengoperasikan CLI tools seperti `zsteg`, `steghide`, dan penulisan parser biner Python kustom tanpa bergantung pada antarmuka GUI.

2. **Mitigasi Defensif & Hardening (Data Loss Prevention / Content Disarm & Reconstruction):**
   - **Content Disarm & Reconstruction (CDR):** Sistem gateway berkas (misalnya upload portal atau email DLP) wajib melakukan normalisasi dan kompresi ulang citra (*image sanitization/re-encoding*) sebelum berkas didistribusikan ke jaringan internal. Mengkonversi citra PNG ke format JPEG lossy atau memetakan ulang palet warna akan mengacak (*wipe*) seluruh bit LSB tanpa merusak visual dokumen.
   - **Kriptografis Bertingkat:** Data sensitif tidak boleh dianggap aman semata-mata karena disembunyikan (*security through obscurity*). Bila pertukaran informasi covert channel terpaksa digunakan, muatan wajib dienkripsi menggunakan cipher standar (misalnya AES-256-GCM) dengan manajemen kunci asimetris.
