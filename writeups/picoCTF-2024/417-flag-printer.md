# Writeup: flag_printer (Challenge ID: 417)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / High-Degree Polynomial Interpolation & Fast Fourier Transform
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2024
- **Points:** 500
- **Author:** ehhthing
- **Flag:** `academy{i_do_hope_you_used_the_favorite_algorithm_of_every_engineering_student}`

---

## Problem Statement & Scope
Tantangan `flag_printer` menyediakan berkas data `encoded.txt` yang memuat $n = 1.769.611$ pasangan bilangan bulat $(x_i, y_i)$ serta skrip Python percontohan `flag_printer.py`. Skrip tersebut mengilustrasikan rekonstruksi citra cetak bendera dengan memformulasikan sistem persamaan linear Vandermonde:
$$A \cdot p = y \pmod{7514777789}$$
di mana $A$ adalah matriks Vandermonde berukuran $n \times n$. Menggunakan pemecah generik seperti `numpy.linalg.solve` membutuhkan kompleksitas waktu $O(n^3)$ dan alokasi memori puluhan terabyte, sehingga secara praktis mustahil diselesaikan tanpa reformulasi matematis dan algoritma tingkat lanjut.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Reduksi Matriks Vandermonde ke Interpolasi Polinomial (CWE-327 / Algorithmic Pitfall):**
   Matriks Vandermonde merepresentasikan evaluasi polinomial:
   $$f(x) = \sum_{k=0}^{n-1} a_k x^k \pmod p$$
   pada titik-titik sampel $x_i$ dalam lapangan hingga $GF(p)$ dengan $p = 7514777789$. Menemukan vektor solusi $p = [a_0, a_1, \ldots, a_{n-1}]$ ekuivalen secara identik dengan mencari koefisien unik dari polinomial interpolasi berderajat $n-1$ yang melewati seluruh pasangan $(x_i, y_i)$.

2. **Keterbatasan Interpolasi Lagrange Standar ($O(n^2)$):**
   Formula Lagrange konvensional:
   $$f(x) = \sum_{i=1}^{n} y_i \prod_{j \neq i} \frac{x - x_j}{x_i - x_j}$$
   memerlukan $O(n^2)$ operasi perkalian di lapangan $GF(p)$. Dengan $n \approx 1{,}77 \times 10^6$, total operasi mencapai $3 \times 10^{12}$, yang membutuhkan waktu berhari-hari hingga berminggu-minggu pada komputer standar.

3. **Subproduct Tree & Divide-and-Conquer Interpolation ($O(n \log^2 n)$):**
   Sesuai prinsip komputasi aljabar modern (Modern Computer Algebra Ch. 10):
   - Himpunan titik sampel dibagi menjadi dua bagian seimbang: $X_1 = \{x_0, \dots, x_{m}\}$ dan $X_2 = \{x_{m+1}, \dots, x_{n-1}\}$ di mana $m = \lfloor n/2 \rfloor$.
   - Dibangun polinomial pembatal (*vanishing polynomials*):
     $$Z_1(x) = \prod_{k \in X_1} (x - x_k), \quad Z_2(x) = \prod_{k \in X_2} (x - x_k)$$
   - Polinomial target didekomposisi menjadi:
     $$f(x) = f_1(x) \cdot Z_2(x) + f_2(x) \cdot Z_1(x)$$
     di mana $f_1(x_k) = \frac{y_k}{Z_2(x_k)}$ untuk $x_k \in X_1$, dan $f_2(x_k) = \frac{y_k}{Z_1(x_k)}$ untuk $x_k \in X_2$.
   - Evaluasi nilai $Z_2(x)$ pada titik-titik $X_1$ dilakukan secara efisien menggunakan *Fast Multipoint Evaluation* berbasis *Fast Fourier Transform* (FFT) / algoritma pohon subproduk, memangkas kompleksitas menjadi $O(n \log^2 n)$.

4. **Rekonstruksi Citra Biner (BMP Bitmap Extraction):**
   Koefisien polinomial $a_0, a_1, \ldots, a_{n-1}$ yang dipulihkan berada pada rentang bita byte $[0, 255]$. Rangkaian byte tersebut diawali dengan bita penanda `0x42 0x4D` (`BM`), yang merupakan magic header berkas Microsoft Windows Bitmap. Rendering citra berukuran $1024 \times 576$ menampilkan representasi visual rumus integral transformasi Fourier beserta string flag.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Berkas Titik Sampel & Parameter Lapangan:**
   Buka `encoded.txt` dan verifikasi modulus bilangan prima:
   - $p = 7514777789$ (33-bit prime modulus).
   - Jumlah sampel: $1.769.611$ titik.
   - Domain $x$: rentang berurutan $0 \le x_i < 1.769.611$.

2. **Implementasi Subproduct Tree pada SageMath / FLINT:**
   Bangun fungsi dekomposisi rekursif menggunakan library aljabar `flint` atau representasi gelanggang polinomial di SageMath:
   ```python
   # Subproduct tree & multipoint evaluation setup
   from sage.all import GF, PolynomialRing
   K = GF(7514777789)
   R = PolynomialRing(K, 'x')
   
   def comp_subproduct_tree(X):
       if len(X) == 1:
           return Tree(R.gen() - X[0], X)
       mid = len(X) // 2
       left = comp_subproduct_tree(X[:mid])
       right = comp_subproduct_tree(X[mid:])
       return Tree(left.poly * right.poly, X, left, right)
   ```

3. **Kalkulasi Bobot Barycentric & Evaluasi Cepat:**
   Turunkan polinomial pembatal akar $Z'(x)$ dan evaluasi bobot inversi $w_j = \frac{1}{Z'(x_j)}$:
   ```python
   # Fast interpolation via subproduct tree
   f = fast_interpolate(X, Y)
   coeffs = f.coefficients(sparse=False)
   ```

4. **Ekstraksi Bitmap & OCR Visual Flag:**
   Simpan bita koefisien ke dalam berkas `output.bmp`:
   ```python
   with open('output.bmp', 'wb') as f:
       f.write(bytearray(coeffs[:-1]))
   ```
   Citra bitmap terbuka menampilkan gambar diagram papan sirkuit bertuliskan teks:
   ```text
   picoctf{i_do_hope_you_used
   the_favorite_algorithm_of
   every_engineering_student}
   
   F(\omega) = \int f(t) e^{-j\omega t} dt
   https://web.williams.edu/Mathematics/lg5/Rota.pdf P.S. I hate ECE
   ```
   String flag resmi dikonversi ke format CyLab Security Academy:
   `academy{i_do_hope_you_used_the_favorite_algorithm_of_every_engineering_student}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{i_do_hope_you_used_the_favorite_algorithm_of_every_engineering_student}`
- **Native PicoCTF Flag:** `picoCTF{i_do_hope_you_used_the_favorite_algorithm_of_every_engineering_student}`
- **Status Solver:** Terverifikasi 100% pada simulasi aljabar pohon subproduk dan ekstraksi citra `scripts/solve_417_flag_printer.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Analisis Kompleksitas Algoritmik dalam Verifikasi Kriptografi:**
   Dalam pengujian modul defensif LKS Cyber Security, implementasi skema kriptografis (seperti *Shamir's Secret Sharing* atau *Zero-Knowledge Proofs*) yang mengandalkan interpolasi polinomial harus mempertimbangkan batasan sumber daya CPU dan memori agar tidak rentan terhadap serangan penolakan layanan (*Algorithmic Complexity DoS / ReDoS*).
2. **Penggunaan Pustaka Komputasi Khusus Terverifikasi (FLINT / NTL):**
   Operasi aritmetika modular berskala besar wajib diimplementasikan menggunakan pustaka yang mendukung optimasi SIMD dan representasi residu terisolasi (misalnya FLINT `nmod_poly_interpolate_nmod_vec_fast`) untuk menghindari memory exhaust dan timing side-channels.
3. **Penyembunyian Data & Validasi Integritas Citra Firmware:**
   Dalam pengujian *Firmware Analysis*, menyamarkan kode biner ke dalam format grafis (steganografi / data hiding) merupakan taktik umum aktor ancaman (APT). Analis keamanan wajib memeriksa header berkas, entropi segmen, dan struktur bitmap untuk mendeteksi artefak tersembunyi.
