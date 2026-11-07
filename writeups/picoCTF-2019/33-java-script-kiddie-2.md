# Writeup: Java Script Kiddie 2 (Challenge ID: 33)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Client-Side Obfuscation, Key Length Parsing & PNG Inversion
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 450
- **Author:** John Johnson
- **Flag:** `academy{358283c70402f9dd5e5d1708c257dac7}`

---

## Problem Statement & Scope
Tantangan `Java Script Kiddie 2` merupakan kelanjutan dari tantangan `Java Script Kiddie`. Halaman web menyajikan formulir yang meminta kunci numerik berukuran 32-karakter (dua kali lebih panjang dari varian pertama). Array data mentah byte diunduh melalui `GET /bytes` berukuran 704 byte. Logika perakitan gambar di sisi klien (`assemble_png`) mengimplementasikan transposisi siklis kolom dengan pemotongan substring kunci. Jika kunci yang dimasukkan valid, gambar QR Code akan berhasil didekompresi dan ditampilkan ke layar.

Ruang lingkup audit ini berfokus pada analisis mendalam terhadap parsing indeks substring pada script browser, dekomposisi spesifikasi biner RFC 2083, dan mitigasi kelemahan penanganan rahasia sisi klien berdasarkan standar **NIST SP 800-115 Section 4.3**.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kegagalan Validasi Parsing Input & Pemotongan String Substring (CWE-20 & CWE-656):**
   Meskipun formulir meminta kunci sepanjang 32 karakter (`key.length == 32`), inspeksi terhadap kode parser perakitan mengungkapkan:
   ```javascript
   var LEN = 16;
   var key = "00000000000000000000000000000000";
   for(var i = 0; i < LEN; i++){
       shifter = Number(key.slice((i*2),(i*2)+1));
       for(var j = 0; j < (bytes.length / LEN); j ++){
           result[(j * LEN) + i] = bytes[(((j + shifter) * LEN) % bytes.length) + i]
       }
   }
   ```
   Pemanggilan `key.slice((i * 2), (i * 2) + 1)` hanya mengambil **1 karakter tunggal** pada indeks genap ($2i$). Karakter pada indeks ganjil ($2i + 1$) tidak pernah diproses oleh algoritma pergeseran. Ini berarti bahwa panjang kunci efektif tetaplah 16 digit, bukan 32 digit.

2. **Dekomposisi Matriks Transposisi Siklis:**
   Array byte memiliki total panjang 704 byte, yang tersusun atas matriks 44 baris $\times$ 16 kolom ($44 \times 16 = 704$).
   Setiap kolom $i \in [0, 15]$ digeser secara siklis sebesar $s_i \in [0, 9]$.
   Untuk baris pertama ($j = 0$):
   $$\text{result}[i] = \text{bytes}[(s_i \times 16 \pmod{704}) + i]$$

3. **Inversi Header Standar PNG (RFC 2083 Known Plaintext):**
   Sebagaimana pada spesifikasi PNG standar, 16 byte pertama harus cocok dengan:
   - File Signature (8 byte): `0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A`
   - IHDR Chunk Size (4 byte): `0x00 0x00 0x00 0x0D`
   - IHDR Chunk Name (4 byte): `0x49 0x48 0x44 0x52`

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Kendala Kolom Header:**
   - Evaluasi setiap kolom $i \in [0, 15]$ dengan mencocokkan `bytes[(s * 16) % 704 + i]` terhadap nilai byte header PNG yang diharapkan.
   - Hasil pencarian calon nilai $s_i$:
     - Kolom 0 s/d 8: masing-masing 1 kandidat unik.
     - Kolom 9: 2 kandidat `[7, 8]`.
     - Kolom 10: 3 kandidat `[7, 8, 9]`.
     - Kolom 11 s/d 15: masing-masing 1 kandidat unik.
   - Ruang pencarian kandidat hanya terdiri dari $1 \times 2 \times 3 = 6$ kemungkinan kombinasi.

2. **Penyaringan Integritas Gambar & Dekompresi:**
   - Bangun array perakitan untuk ke-6 kombinasi dan periksa keberadaan penutup chunk PNG `IEND\xaeB`\x82`.
   - Hanya kombinasi pergeseran berikut yang menghasilkan file PNG yang valid:
     $$s = [0, 8, 1, 3, 0, 6, 6, 2, 7, 7, 8, 4, 0, 1, 2, 3]$$
   - Karena algoritma mengambil karakter pada indeks genap, kunci dapat dibentuk dengan menyisipkan karakter '0' pada indeks ganjil:
     $$\text{Key}_{32} = 00801030006060207070804000102030$$

3. **Pemindaian Barcode & Ekstraksi Flag:**
   - Muat gambar PNG yang dihasilkan ($370 \times 370$ monochrome QR code) ke mesin pemindai barcode `zbarimg`.
   - Barcode terbaca: `QR-Code:academy{358283c70402f9dd5e5d1708c257dac7}`.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{358283c70402f9dd5e5d1708c257dac7}`
- **Komunitas Standar (CTF Format):** `CTF{358283c70402f9dd5e5d1708c257dac7}`
- **Status Verifikasi:** REST API CyLab `POST /api/submissions/` mengembalikan `HTTP 201 Created` dengan `correct: true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Bahaya False Security dari Kompleksitas Semu:**
   Menambah panjang kunci dari 16 menjadi 32 karakter tidak meningkatkan keamanan jika logika implementasi pemrosesan hanya mengevaluasi separuh dari panjang kunci tersebut. Dalam audit keamanan LKS, pemeriksa harus selalu memverifikasi logika parser aktual dan aliran data (*data flow tracing*), bukan hanya mempercayai tampilan formulir.
2. **Eliminasi Client-Side Cryptographic Schemes:**
   Semua enkripsi dan kontrol akses data multimedia harus dieksekusi di backend server yang terlindungi (*defense-in-depth*). Transmisi aset rahasia dalam bentuk biner yang dapat dipetakan langsung di peramban pengguna adalah pelanggaran mendasar prinsip arsitektur keamanan web.
3. **Penerapan NIST SP 800-115:**
   Terapkan pengujian penetrasi berbasis kotak putih (*white-box penetration testing*) untuk menelusuri bagaimana parameter input pengguna berinteraksi dengan struktur data internal, guna mencegah bypass autentikasi dan penyingkapan aset terproteksi.
