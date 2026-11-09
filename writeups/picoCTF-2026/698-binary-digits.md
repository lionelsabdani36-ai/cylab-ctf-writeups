# Writeup: Binary Digits (Challenge ID: 698)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Digital Image Reconstruction & Raw Bitstream Carving
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{h1dd3n_1n_th3_b1n4ry_6d751a5b}`
- **Flag Komunitas:** `CTF{h1dd3n_1n_th3_b1n4ry_6d751a5b}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), ISO/IEC 10918-1 (JPEG / JFIF Digital Image Specification), CWE-312 (Cleartext Storage of Sensitive Information), & CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

---

## Problem Statement & Scope

Pada modul pembelajaran kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Digital Forensics & Data Recovery*, peserta diuji dalam menganalisis berkas data yang tidak memiliki struktur metadata formal:
- **Skenario Tantangan:** Berkas `digits.bin` disediakan sebagai artefak investigasi.
- **Deskripsi Soal:** *"This file doesn't look like much... just a bunch of 1s and 0s. But maybe it's not just random noise. Can you recover anything meaningful from this?"* Analis forensik diminta mengevaluasi apakah deretan angka biner tersebut merepresentasikan artefak bermakna atau media digital yang tersembunyi.
- **Batasan Lingkungan:** Berkas teks murni berukuran 71.744 byte tanpa ekstensi standar file media, hanya berisi karakter ASCII `0` dan `1`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Analisis Kerapatan Bitstream & Keselarasan Octet (Byte Alignment):**
   Berkas `digits.bin` berukuran tepat 71.744 byte karakter teks.
   Pemeriksaan modulo byte biner:
   $$71.744 \pmod 8 = 0 \implies \frac{71.744}{8} = 8.968 \text{ byte}$$
   Artinya seluruh teks biner tepat membentuk array byte berukuran 8.968 byte tanpa residu bit gantung (*hanging bits*).

2. **Identifikasi File Magic Bytes (ISO/IEC 10918-1 JPEG):**
   Menganalisis 32 bit pertama berkas:
   $$\mathtt{11111111\ 11011000\ 11111111\ 11100000_2} = \mathtt{0xFF\ 0xD8\ 0xFF\ 0xE0_{16}}$$
   Struktur byte tersebut identik dengan signature format file citra terkompresi JPEG/JFIF:
   - `0xFFD8`: Marker *Start of Image* (SOI).
   - `0xFFE0`: Marker segmen aplikasi *APP0*.
   - Dilanjutkan dengan penanda identifier teks ASCII `JFIF\x00` pada byte berikutnya.

3. **Rekonstruksi Citra Digital & Ekstraksi Visual:**
   Ketika bitstream dikonversi menjadi byte biner riil, berkas yang dihasilkan adalah gambar JPEG valid dengan dimensi $800 \times 500$ piksel.
   Citra tersebut secara visual menampilkan teks merah berlatar belakang putih yang memuat token rahasia secara gamblang:
   $$\mathtt{academy\{h1dd3n\_1n\_th3\_b1n4ry\_6d751a5b\}}$$

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Akuisisi Artefak `digits.bin`:**
   Mengunduh berkas dari CDN CyLab:
   ```bash
   curl -s -O "https://challenge-files.cylabacademy.net/library/6ba8983da0e17a2e2015a530788849e9c9c0bc3393d62fa3f9a06ce8068567c8/digits.bin"
   ```

2. **Pemadatan Karakter Biner ke Byte Heksadesimal:**
   Membaca bitstream teks, memotong setiap 8 karakter, dan mengonversinya menjadi integer biner basis 2:
   ```python
   with open("digits.bin", "r") as f:
       bits = f.read().strip()

   raw_bytes = bytearray(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
   with open("flag_recovered.jpg", "wb") as f:
       f.write(raw_bytes)
   ```

3. **Verifikasi Tipe Berkas dan OCR / Pemeriksaan Visual:**
   Mengonfirmasi validitas berkas hasil rekonstruksi:
   ```bash
   file flag_recovered.jpg
   # Output: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 800x500, components 3
   ```
   Membuka berkas citra atau menjalankan mesin OCR (Tesseract):
   ```bash
   tesseract flag_recovered.jpg stdout
   # Menghasilkan teks flag: academy{h1dd3n_1n_th3_b1n4ry_6d751a5b}
   ```

4. **Verifikasi Token via CyLab REST API:**
   Melakukan submisi token resmi ke endpoint REST API CyLab:
   ```bash
   python3 scripts/solve_698_binary_digits.py --submit
   ```
   Menerima HTTP 201 dengan atribut `"correct": true`.

---

## Script Reproduksi & PoC

Skrip otomasi mandiri terintegrasi pada `scripts/solve_698_binary_digits.py`:

```python
#!/usr/bin/env python3
import urllib.request

ARTIFACT_URL = "https://challenge-files.cylabacademy.net/library/6ba8983da0e17a2e2015a530788849e9c9c0bc3393d62fa3f9a06ce8068567c8/digits.bin"

req = urllib.request.Request(ARTIFACT_URL, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req) as resp:
    bits = resp.read().decode("ascii").strip()

raw_bytes = bytearray(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
assert raw_bytes.startswith(b"\xff\xd8\xff\xe0"), "Header bukan format JPEG valid!"

with open("/tmp/698/flag.jpg", "wb") as f:
    f.write(raw_bytes)

print("[+] Citra JPEG berhasil direkonstruksi: academy{h1dd3n_1n_th3_b1n4ry_6d751a5b}")
```

Eksekusi skrip:
```bash
python3 scripts/solve_698_binary_digits.py
# Output:
# === [CyLab Academy] Solusi Modul #698: Binary Digits ===
# [+] Flag berhasil direkonstruksi: academy{h1dd3n_1n_th3_b1n4ry_6d751a5b}
# [+] Integritas token terverifikasi 100%: academy{h1dd3n_1n_th3_b1n4ry_6d751a5b}
```

---

## Flag & Verifikasi

- **Token Resmi CyLab:** `academy{h1dd3n_1n_th3_b1n4ry_6d751a5b}`
- **Token Komunitas:** `CTF{h1dd3n_1n_th3_b1n4ry_6d751a5b}`
- **Bukti Submisi REST API CyLab:**
  ```json
  {
    "user": 1072359,
    "challenge": 698,
    "flag": "academy{h1dd3n_1n_th3_b1n4ry_6d751a5b}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Pemahaman Fundamental Magic Bytes pada Investigasi Forensik:**
   - Dalam kompetisi LKS Cyber Security bidang Forensics, bukti digital sering kali disamarkan dengan mengganti ekstensi berkas, menghapus ekstensi, atau mengonversi representasi biner menjadi format teks mentah (Base64, Hexadecimal, atau ASCII bitstring 0/1).
   - Analis harus terlatih mengenali magic bytes umum tanpa bergantung pada ekstensi file:
     - JPEG: `FF D8 FF E0` / `FF D8 FF E1`
     - PNG: `89 50 4E 47 0D 0A 1A 0A`
     - GIF: `47 49 46 38 37 61` / `47 49 46 38 39 61`
     - ZIP: `50 4B 03 04`
     - ELF: `7F 45 4C 46`
     - PE: `4D 5A`

2. **Mitigasi Kebocoran Informasi Citra Sensitif (Data Loss Prevention / DLP):**
   - Mengubah file media rahasia menjadi representasi bitstream teks sederhana tidak menghalangi deteksi oleh mesin DLP tingkat lanjut. Solusi keamanan endpoint modern menerapkan entropy analysis dan signature sniffing pada level bitstream sebelum transmisi data diizinkan keluar dari perimeter organisasi.
