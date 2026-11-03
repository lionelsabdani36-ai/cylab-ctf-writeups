# Writeup: miniRSA (Challenge ID: 73)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography
- **Difficulty:** Hard (3)
- **Author:** speeeday/Danny
- **Event:** picoCTF 2019
- **Points:** 300
- **Flag:** `academy{n33d_a_lArg3r_e_e2b360ae}`

---

## Deskripsi Tantangan
> Let's decrypt this. Can you decrypt this ciphertext?
> Download artifact:
> - `ciphertext`: Berisi nilai modulus publik $N$, eksponen publik $e = 3$, dan ciphertext $c$.
>
> Hint:
> 1. RSA tutorial: What is the math behind RSA?
> 2. How is ciphertext computed from plaintext and keys?
> 3. Does $e$ need to be small?

---

## Analisis Kerentanan & Konsep Teknis (Root Cause Theory)
1. **Kelemahan Public Exponent Kecil Tanpa Padding (Low Public Exponent Attack):**
   - Dalam kriptosistem RSA textbook, ciphertext $c$ dihitung berdasarkan relasi:
     $$c \equiv m^e \pmod N$$
   - Ketika eksponen publik $e$ dipilih bernilai sangat kecil (dalam hal ini $e = 3$) dan pesan $m$ tidak di-pad secara acak menggunakan skema standar industri seperti RSA-OAEP (*Optimal Asymmetric Encryption Padding*), panjang pesan $|m|$ dapat menghasilkan nilai numerik sedemikian rupa sehingga:
     $$m^3 < N$$
   - Jika kondisi $m^3 < N$ terpenuhi, maka operasi modular reduction ($\pmod N$) sebenarnya tidak pernah terjadi dalam proses komputasi aritmatika integer:
     $$c = m^3 \pmod N = m^3 \quad (\text{over } \mathbb{Z})$$
   - Akibatnya, pemulihan pesan teks asli $m$ dapat dilakukan secara deterministik tanpa perlu mengetahui faktor prima modulus $p$ dan $q$, maupun menghitung kunci privat $d$, melainkan hanya dengan menghitung akar pangkat tiga bilangan bulat (*integer cube root*):
     $$m = \sqrt[3]{c}$$
2. **Generalisasi Small-k Search:**
   - Bahkan jika $m^3$ sedikit lebih besar dari modulus $N$, nilainya hanya akan melintasi batas modulus beberapa kali ($k$ kecil):
     $$c = m^3 - k \cdot N \implies m = \sqrt[3]{c + k \cdot N}$$
   - Pada tantangan ini, nilai $c$ berukuran ~550 digit desimal sedangkan $N$ berukuran 617 digit desimal (2048-bit), sehingga secara matematis $m^3 < N$ ($k = 0$).

---

## Rekonstruksi Pengujian Step-by-Step
1. **Inspeksi Parameter Publik:**
   - Mengunduh artefak `ciphertext` dari CDN resmi CyLab.
   - Mengekstrak parameter:
     - $N$: Modulus integer 2048-bit (~617 digit desimal).
     - $e = 3$.
     - $c$: Ciphertext integer (~550 digit desimal).
2. **Evaluasi Batas Integer & Cube Root:**
   - Karena $c$ adalah representasi integer sangat besar (>1024 bit), penggunaan fungsi floating-point standar seperti `c ** (1/3)` akan mengalami kegagalan `OverflowError` atau kehilangan presisi (*loss of significance*).
   - Mengimplementasikan pencarian biner integer murni (*pure integer binary search*):
     $$\text{lo} = 1, \quad \text{hi} = 1 \ll \left\lceil \frac{\text{bit\_length}(c)}{3} \right\rceil$$
   - Melakukan konvergensi biner hingga $\text{mid}^3 == c$.
3. **Ekstraksi Plaintext & Validasi Token:**
   - Hasil pencarian biner integer menghasilkan nilai $m$ yang tepat.
   - Mengonversi integer $m$ ke deretan byte big-endian via `m.to_bytes(...)`:
     `academy{n33d_a_lArg3r_e_e2b360ae}`.
4. **Verifikasi REST API CyLab:**
   - Mengirimkan token ke endpoint `POST /api/submissions/` dengan payload:
     `{"challenge": 73, "flag": "academy{n33d_a_lArg3r_e_e2b360ae}"}`
   - Respons server mengonfirmasi validitas dengan status `HTTP 201 Created` (`correct: true`).

---

## Flag & Verifikasi
- **Token Resmi:** `academy{n33d_a_lArg3r_e_e2b360ae}`
- **API Response:** `{"user": 1072359, "challenge": 73, "flag": "academy{n33d_a_lArg3r_e_e2b360ae}", "correct": true, "historical": false}`
- **Solver Script:** `scripts/solve_73_minirsa.py`

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Kepatuhan NIST SP 800-56B Rev. 2 & FIPS 186-4:**
  - Standar kriptografi modern melarang penggunaan eksponen publik $e < 65537$ (`2^16 + 1`). Nilai $e = 65537$ memberikan proteksi optimal terhadap serangan low exponent (Coppersmith, Håstad, integer root) sekaligus mempertahankan efisiensi enkripsi melalui representasi biner `10000000000000001` (hanya membutuhkan 17 perkalian & kuadrat modular).
- **Mandatory Random Padding (PKCS#1 v2.2 / OAEP):**
  - Enkripsi RSA asimetris tidak boleh dioperasikan dalam mode "raw/textbook". Wajib menerapkan *Optimal Asymmetric Encryption Padding* (RSA-OAEP) dengan fungsi hash kriptografis aman (SHA-256) untuk menjamin sifat *indistinguishability under chosen-ciphertext attack* (IND-CCA2) dan memastikan panjang pesan terdistribusi merata di seluruh ruang modulus $N$.
