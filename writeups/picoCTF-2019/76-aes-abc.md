# Writeup: AES-ABC (Challenge ID: 76)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography
- **Difficulty:** Hard (3)
- **Author:** waituckw
- **Event:** picoCTF 2019
- **Points:** 400
- **Flag:** `academy{d0Nt_r0ll_yoUr_0wN_aES}`

---

## Deskripsi Tantangan
> AES-ECB is bad, so I rolled my own cipher block chaining mechanism - Addition Block Chaining!
> Download artifacts:
> - `aes-abc.py`: Skrip Python enkripsi kustom menggunakan kombinasi AES-ECB dan skema modular addition chaining.
> - `body.enc.ppm`: Berkas gambar PPM terenkripsi yang berisi flag tersembunyi.
>
> Hint:
> 1. You probably want to figure out what the flag looks like in ECB form...

---

## Analisis Kerentanan & Konsep Teknis (Root Cause Theory)
1. **Kegagalan Skema "Roll Your Own Crypto" (CWE-327: Use of a Broken or Risky Cryptographic Algorithm):**
   - Penulis tantangan menyadari kerentanan Electronic Codebook (ECB) mode, namun alih-alih menggunakan standar mode terbukti seperti CBC, CTR, atau GCM (NIST SP 800-38A), ia mengimplementasikan skema chaining kustom bernama *Addition Block Chaining* (ABC).
   - Pada `aes-abc.py`, proses enkripsi dilakukan dengan:
     1. Menghitung ciphertext ECB standar: $C = \text{AES-ECB}(P)$.
     2. Membagi $C$ menjadi blok-blok 16-byte $C_1, C_2, \dots, C_m$.
     3. Menambahkan blok inisialisasi acak $B_0 = \text{IV}$.
     4. Menghitung blok ciphertext terenkripsi $B_i$ secara berulang:
        $$B_i = (B_{i-1} + C_i) \pmod{\text{UMAX}}, \quad \text{di mana } \text{UMAX} = 256^{16} = 2^{128}$$
2. **Reversibilitas Linier Modular Addition Chaining:**
   - Operasi penambahan modular atas integer modulo $2^{128}$ merupakan relasi linier yang sepenuhnya dapat dibalik (*reversible*) tanpa memerlukan kunci rahasia ($\text{KEY}$):
     $$C_i = (B_i - B_{i-1}) \pmod{\text{UMAX}}$$
   - Dengan menghitung selisih modular antara dua blok terenkripsi yang berturutan dalam `body.enc.ppm`, seluruh deretan blok ciphertext $C_1, C_2, \dots, C_m$ dalam mode AES-ECB murni dapat direkonstruksi 100%.
3. **Kelemahan Deterministik AES-ECB (ECB Penguin Effect):**
   - Dalam mode ECB, tidak ada pengacakan (non-randomized) antar blok data: setiap blok plaintext 16-byte yang identik akan selalu menghasilkan blok ciphertext 16-byte yang identik:
     $$P_i = P_j \implies C_i = C_j$$
   - Format gambar raster tak terkompresi seperti Portable Pixmap (PPM P6) menyimpan byte piksel RGB secara langsung. Area latar belakang (*background*) yang seragam memiliki pola berulang yang menghasilkan blok ciphertext ECB yang sama secara masif.
   - Akibatnya, pola visual teks flag yang berbeda dari latar belakang tetap terpapar secara kasat mata melalui kontras distribusi blok ciphertext ECB.

---

## Rekonstruksi Pengujian Step-by-Step
1. **Ekstraksi Header & Parsing Blok PPM:**
   - Membaca 3 baris pertama berkas `body.enc.ppm` untuk mempertahankan metadata PPM (`P6\n1895 820\n255\n`).
   - Memisahkan payload terenkripsi ke dalam 291.358 blok 16-byte ($B_0 = \text{IV}, B_1, \dots$).
2. **Dekripsi ABC ke ECB Chaining:**
   - Menghitung $C_i = (B_i - B_{i-1}) \pmod{2^{128}}$ untuk setiap $i \in [1, \text{len}(B)-1]$.
   - Mengonversi integer $C_i$ ke representasi 16-byte big-endian.
   - Menggabungkan seluruh blok hasil dekripsi modular bersama header asli ke dalam berkas `body.ecb.ppm`.
3. **Analisis Frekuensi Blok & Binarisasi Kontras:**
   - Menghitung kemunculan setiap blok 16-byte pada data ECB yang dipulihkan.
   - Blok paling dominan adalah latar belakang gambar (kemunculan 284.103 kali dari 291.357 blok total):
     $$\text{Background Block: } \texttt{c603bd7537be859d3f69e0c20ab77f6b}$$
   - Memetakan blok latar belakang ke nilai putih (`0xFF`) dan blok-blok non-latar belakang ke nilai hitam (`0x00`) untuk menghasilkan gambar biner beresolusi tinggi `clean.ppm`.
4. **Ekstraksi OCR & Visual Inspection:**
   - Mengonversi `clean.ppm` ke format PNG menggunakan FFmpeg dan mengeksekusi OCR Tesseract serta pemetaan ASCII art beresolusi tinggi pada koordinat $X=[167, 1894], Y=[336, 819]$.
   - Teks glif visual terbaca secara akurat:
     `academy{d0Nt_r0ll_yoUr_0wN_aES}`.
5. **Verifikasi REST API CyLab:**
   - Mengirimkan token ke endpoint `POST /api/submissions/` dengan payload:
     `{"challenge": 76, "flag": "academy{d0Nt_r0ll_yoUr_0wN_aES}"}`
   - Respons server mengonfirmasi validitas dengan status `HTTP 201 Created` (`correct: true`).

---

## Flag & Verifikasi
- **Token Resmi:** `academy{d0Nt_r0ll_yoUr_0wN_aES}`
- **API Response:** `{"user": 1072359, "challenge": 76, "flag": "academy{d0Nt_r0ll_yoUr_0wN_aES}", "correct": true, "historical": false}`
- **Solver Script:** `scripts/solve_76_aes_abc.py`

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Larangan "Roll Your Own Crypto" (NIST SP 800-175B):**
  - Praktik merancang atau memodifikasi algoritma enkripsi dan chaining mode secara mandiri sangat rentan terhadap cacat struktural matematis. Selalu gunakan standar mode operasi yang telah dievaluasi dan distandarisasi oleh NIST (SP 800-38A, SP 800-38D).
- **Penggunaan Mode Terotentikasi (Authenticated Encryption with Associated Data - AEAD):**
  - Mode enkripsi modern wajib menyediakan kerahasiaan (*confidentiality*) dan integritas (*integrity*) sekaligus. Standar industri seperti AES-GCM (*Galois/Counter Mode*) atau ChaCha20-Poly1305 (RFC 8439) melindungi data dari serangan manipulasi blok, modifikasi ciphertext (*malleability*), serta kebocoran pola ECB.
