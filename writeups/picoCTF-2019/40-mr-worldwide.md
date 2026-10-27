# Writeup: Mr-Worldwide (Challenge ID: 40)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Geocoding Coordinate Mapping
- **Difficulty:** Medium
- **Author:** Danny
- **Event:** picoCTF 2019
- **Points:** 200
- **Flag:** `academy{KODIAK_ALASKA}`

---

## Problem Statement & Scope
Disediakan berkas `message.txt` berisi serangkaian koordinat geografis (lintang dan bujur) yang dibungkus dalam format flag `academy{(lat, lon)..._(lat, lon)...}`. Analis diminta untuk memecahkan kode tersembunyi di balik koordinat-koordinat tersebut.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Steganografi Geografis & Acrostic City Mapping:** Setiap pasangan koordinat lintang dan bujur mengacu secara spesifik pada pusat kota global (geographical landmark). Huruf pertama dari nama kota tersebut membentuk pesan akrostik (*first-letter acrostic mnemonic*).
2. **Ketiadaan Kompleksitas Kriptografis:** Tantangan ini tidak menggunakan enkripsi matematis, melainkan substitusi berbasis pengetahuan umum/OSINT geolokasi. Setelah pola pemetaan nama kota diidentifikasi, pesan dapat dipulihkan secara deterministik.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis koordinat pada berkas `message.txt`:
   - Bagian 1 (Sebelum `_`):
     - `(35.028309, 135.753082)` $\rightarrow$ Kyoto, Jepang $\rightarrow$ **K**
     - `(46.469391, 30.740883)` $\rightarrow$ Odessa, Ukraina $\rightarrow$ **O**
     - `(39.758949, -84.191605)` $\rightarrow$ Dayton, Ohio, USA $\rightarrow$ **D**
     - `(41.015137, 28.979530)` $\rightarrow$ Istanbul, Turki $\rightarrow$ **I**
     - `(24.466667, 54.366669)` $\rightarrow$ Abu Dhabi, UEA $\rightarrow$ **A**
     - `(3.140853, 101.693207)` $\rightarrow$ Kuala Lumpur, Malaysia $\rightarrow$ **K**
     - Kata 1: **KODIAK**
   - Bagian 2 (Setelah `_`):
     - `(9.005401, 38.763611)` $\rightarrow$ Addis Ababa, Ethiopia $\rightarrow$ **A**
     - `(-3.989038, -79.203560)` $\rightarrow$ Loja, Ekuador $\rightarrow$ **L**
     - `(52.377956, 4.897070)` $\rightarrow$ Amsterdam, Belanda $\rightarrow$ **A**
     - `(41.085651, -73.858467)` $\rightarrow$ Sleepy Hollow, New York, USA $\rightarrow$ **S**
     - `(57.790001, -152.407227)` $\rightarrow$ Kodiak, Alaska, USA $\rightarrow$ **K**
     - `(31.205753, 29.924526)` $\rightarrow$ Alexandria, Mesir $\rightarrow$ **A**
     - Kata 2: **ALASKA**
2. Gabungkan kedua kata dengan pemisah underscore:
   `KODIAK_ALASKA`
3. Susun flag resmi: `academy{KODIAK_ALASKA}`.
4. Eksekusi solver Python:
   ```bash
   python3 scripts/solve_40_mr_worldwide.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{KODIAK_ALASKA}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **OSINT & Sanitasi Data Geospasial:** Dalam investigasi keamanan siber dan modul OSINT LKS, informasi metadata geolokasi (EXIF GPS) pada berkas foto atau log perutean sering kali menjadi vektor kebocoran data sensitif yang memungkinkan profiling lokasi fisik aset penting.
