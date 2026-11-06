# Writeup: MSS_ADVANCE Revenge (Challenge ID: 709)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography
- **Difficulty:** Hard
- **Event:** picoCTF 2026
- **Points:** 400
- **Author:** Cayden (SuperBeetleGamer) Liao
- **Flag:** `academy{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`

---

## Problem Statement & Scope
Tantangan `MSS_ADVANCE Revenge` menghadirkan skema pembagian rahasia modular (*modular secret sharing scheme*) berbasis polinomial berderajat 29 ($n = 30$ koefisien) atas modulo bilangan prima besar 1024-bit $p$:
$$f(x) = \sum_{j=0}^{29} c_j \cdot x^{29 - j} \pmod p$$
Server hanya menyediakan 20 pasangan evaluasi publik $(x_i, y_i)$ di mana $y_i = f(x_i) \pmod p$, sehingga sistem persamaan linier berada dalam kondisi *underdetermined* (20 persamaan dengan 30 variabel koefisien bebas). Koefisien $c_0$ adalah kunci rahasia 256-bit yang digunakan untuk mengenkripsi flag melalui algoritma AES-256-CBC dengan IV statis. Koefisien turunan dihasilkan secara deterministik menggunakan rantai SHA-256 ($c_{j+1} = \text{SHA256}(c_j)$), yang memastikan setiap koefisien berukuran relatif kecil dibandingkan dengan modulus 1024-bit ($c_j < 2^{256} \ll p$). Sasaran audit kriptografi adalah merumuskan sistem persamaan sebagai masalah vektor terpendek pada kisi (*Shortest Vector Problem* / SVP) dan menerapkan reduksi basis kisi Lenstra–Lenstra–Lovász (LLL) untuk mengekstrak koefisien $c_0$ dan mendekripsi bendera.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Underdetermined Polynomial Secret Sharing & Batas Koefisien Kecil (CWE-327):**
   Secara teoritis, interpolasi Lagrange membutuhkan minimal $k$ titik evaluasi untuk merekonstruksi polinomial derajat $k-1$. Namun, ketika koefisien polinomial dibatasi pada rentang nilai yang sangat kecil dibandingkan dengan modulus lapangan ($c_j \in [0, 2^{256}]$ vs $p \approx 2^{1024}$), ruang pencarian solusi tidak lagi seragam (*non-uniform distribution*).
2. **Formulasi Kisi Berbobot (Weighted Coppersmith / Kannan Embedding):**
   Relasi evaluasi untuk setiap titik $i \in \{0, \dots, m-1\}$ dapat dinyatakan sebagai:
   $$\sum_{j=0}^{n-1} c_j x_i^{n-1-j} - k_i p = y_i$$
   Dengan memilih konstanta bobot $W = 2^{512}$, kita menyusun kisi dimensi $(m + n + 1) \times (m + n + 1) = 51 \times 51$:
   $$L = \begin{pmatrix} p \cdot W \cdot I_m & 0 & 0 \\ X \cdot W & I_n & 0 \\ -Y \cdot W & 0 & 1 \end{pmatrix}$$
   di mana $X_{j, i} = x_i^{n-1-j} \pmod p$ dan $Y_i = y_i$.
3. **Reduksi Basis Kisi LLL (Lenstra-Lenstra-Lovász):**
   Vektor target $(\vec{0}, c_0, c_1, \dots, c_{29}, 1)$ merupakan elemen kisi dengan norma Euclidean yang sangat pendek ($\|\vec{v}\| \approx \sqrt{30} \cdot 2^{256} \ll 2^{512}$). Algoritma reduksi LLL (diimplementasikan via `fpylll` / FPLLL) mengisolasi vektor ini dalam waktu polinomial, secara langsung mengungkap koefisien $c_0$.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Parsing Parameter Publik Tantangan:**
   Dari `output.txt`, ekstrak modulus 1024-bit $p$, 20 pasangan evaluasi $(x_i, y_i)$, ciphertext AES `enc_flag`, dan IV.
2. **Penyusunan Matriks Basis Kisi Dimensi 51:**
   Inisialisasi `IntegerMatrix(51, 51)` dengan faktor pembobotan $W = 2^{512}$:
   - Baris 0 s.d. 19: Relasi modulo $p \cdot W$ pada diagonal.
   - Baris 20 s.d. 49: Monomial pangkat $x_i^{29-j} \cdot W$ dengan identitas diagonal $1$ untuk melacak koefisien $c_j$.
   - Baris 50: Vektor offset masukan $-y_i \cdot W$ dengan elemen penutup $1$.
3. **Eksekusi Reduksi Basis LLL:**
   Jalankan reduksi basis kisi menggunakan algoritma FPLLL:
   ```python
   from fpylll import IntegerMatrix, LLL
   LLL.reduction(L)
   ```
4. **Isolasi Kunci AES:**
   Pindai baris hasil reduksi untuk menemukan elemen bernilai integer positif berukuran 256-bit:
   `c0 = 0x1d6466f4c437d790ef4ae9ba2c54cf8b406050f8853fb35ba96ad54bcd8edf0b`.
5. **Dekripsi Ciphertext AES-256-CBC:**
   Konversikan $c_0$ menjadi 32 byte biner kunci AES:
   ```python
   key = bytes.fromhex("1d6466f4c437d790ef4ae9ba2c54cf8b406050f8853fb35ba96ad54bcd8edf0b")
   cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex("00000000000000000000000000000000"))
   flag = unpad(cipher.decrypt(bytes.fromhex(enc_flag_hex)), 16)
   ```
   Dekripsi menghasilkan teks terang bendera resmi:
   `picoCTF{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`.
   Dikonversikan ke format resmi CyLab Security Academy:
   `academy{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`
- **Native PicoCTF Flag:** `picoCTF{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`
- **Validasi Algoritma:** Terverifikasi 100% lolos reduksi basis kisi LLL pada `scripts/solve_709_mss_advance_revenge.py`.

---

## Rekomendasi Remediatoris (NIST SP 800-115 & FIPS)
1. **Pemilihan Koefisien Acak Seragam Penuh:**
   Koefisien skema polinomial Shamir harus dipilih secara acak murni dari seluruh rentang lapangan modulo $[0, p-1]$, bukan dari rentang terbatas 256-bit.
2. **Kepatuhan Ambang Batas Titik Evaluasi (*Threshold Enforcement*):**
   Jangan pernah membagikan titik evaluasi yang memungkinkan pembentukan kisi berdimensi rendah tanpa memenuhi jumlah ambang batas minimal ($k \ge n$).
3. **Pemisahan Entropi Kunci Enkripsi:**
   Gunakan fungsi derivasi kunci yang aman (KDF seperti HKDF-SHA512 atau Argon2id) dengan garam (*salt*) terisolasi daripada menggunakan koefisien polinomial mentah sebagai kunci AES.
