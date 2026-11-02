# Writeup: Virtual Machine 0 (Challenge ID: 385)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Mechanical Gear Ratio & Byte Serialization
- **Difficulty:** Medium
- **Author:** Collin Meyer
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{g34r5_0f_m0r3_c95d6542}`

---

## Problem Statement & Scope
Tantangan menyajikan sebuah model rancang bangun mesin mekanik virtual berformat COLLADA 3D (`Virtual-Machine-0.dae`) yang diperoleh dari server lawan, beserta sebuah berkas nilai rotasi input (`input.txt`). Berdasarkan dokumen desain:
- Rotasi sumbu/poros berwarna merah berfungsi sebagai *input*.
- Rotasi sumbu/poros berwarna biru berfungsi sebagai *output*.
- Memutar poros merah sebanyak bilangan yang tertera pada `input.txt` akan menghasilkan rotasi poros biru yang merepresentasikan flag rahasia.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Analisis Rekayasa Balik Mekanikal (Mechanical Kinematic Reverse Engineering):** Berbeda dengan rekayasa balik perangkat lunak konvensional (PE/ELF/Bytecode), tantangan ini menguji kemampuan analisis model representasi 3D dan komputasi analog. Model COLLADA (.dae) mendefinisikan geometri mesh dan hierarki roda gigi (*gear train*).
2. **Rasio Transmisi Roda Gigi (Gear Transmission Ratio):**
   - Roda gigi pemacu (*driver gear*) pada poros merah memiliki $40$ gerigi.
   - Roda gigi yang dipacu (*driven pinion*) yang terhubung langsung ke poros output biru memiliki $8$ gerigi.
   - Rasio roda gigi dihitung secara matematis melalui rumus perbandingan gerigi:
     $$R = \frac{N_{\text{in}}}{N_{\text{out}}} = \frac{40}{8} = 5$$
   - Artinya, untuk setiap 1 putaran penuh pada poros merah, poros biru akan berputar tepat 5 putaran penuh ($5\times$).
3. **Serialisasi Bilangan Arbitrer Besar ke Karakter ASCII:**
   Nilai numerik pada `input.txt` merupakan bilangan integer sangat besar (74 digit desimal):
   $$34414012771923267025329027534276989288205997301964262080788052262850398745$$
   Perkalian nilai tersebut dengan faktor rasio 5 menghasilkan representasi biner flag:
   $$\text{Output} = \text{Input} \times 5$$
   Ketika nilai desimal hasil perkalian dikonversi menjadi representasi heksadesimal (*big-endian byte stream*), setiap pasangan nibble (1 byte) memetakan secara langsung ke kode ASCII karakter flag.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi Struktur Berkas Model 3D:**
   Ekstraksi arsip `Virtual-Machine-0.zip` menghasilkan berkas COLLADA XML `Virtual-Machine-0.dae`.
   Melalui rendering visual menggunakan viewer 3D (seperti 3dviewer.net atau Blender), dilakukan identifikasi komponen mekanis roda gigi input dan output.
2. **Perhitungan Rasio Gerigi:**
   - Menghitung jumlah gerigi roda merah: 40 gerigi.
   - Menghitung jumlah gerigi roda abu-abu penyalur ke poros biru: 8 gerigi.
   - Rasio kecepatan sudut $\omega_{\text{out}} = 5 \times \omega_{\text{in}}$.
3. **Pemodelan Matematis Python Tanpa Simulasi Fisik:**
   Memutar poros secara fisik atau simulasi numerik langkah-demi-langkah sebanyak $10^{73}$ siklus tidak mungkin dilakukan secara komputasi. Oleh karena itu, kita menerapkan pemodelan analitis langsung:
   ```python
   with open('input.txt') as f:
       input_val = int(f.read().strip())
   
   output_val = input_val * 5
   hex_bytes = bytes.fromhex(hex(output_val)[2:])
   flag = hex_bytes.decode('latin-1')
   print(flag)
   ```
4. **Ekstraksi Flag:**
   Hasil dekode aliran byte menghasilkan token flag:
   ```text
   academy{g34r5_0f_m0r3_c95d6542}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{g34r5_0f_m0r3_c95d6542}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 385, "flag": "academy{g34r5_0f_m0r3_c95d6542}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Abstraksi Matematis terhadap Sistem Tertanam / Black Box:** Pada modul Reverse Engineering kompetisi LKS Cyber Security, peserta sering dihadapkan pada mesin virtual kustom atau sistem komputasi non-standar. Kunci keberhasilan terletak pada kemampuan mengidentifikasi fungsi transfer input-ke-output (matriks transformasi / rasio matematika) tanpa terjebak dalam kompleksitas simulasi state mesin per-siklus.
- **Validasi Integritas & Desain Sistem Kontrol Cyber-Physical:** Dalam sistem kontrol industri (ICS / SCADA) dan komputasi fisik, ketergantungan pada rasio mekanikal untuk mengaburkan rahasia sistem adalah bentuk *security through obscurity*. Mekanisme kriptografi digital berbasis standar (seperti AES atau HMAC dengan modul keamanan perangkat keras HSM) harus selalu digunakan untuk otentikasi data dan penegakan integritas.
