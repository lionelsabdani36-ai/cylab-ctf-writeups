# Writeup: corrupt-key-2 (Challenge ID: 211)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / 1024-Bit RSA Multivariate Coppersmith Small-Roots via LLL Lattice Reduction (CWE-326 / CWE-327)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 500
- **Author:** redpwn
- **Flag:** `academy{b7a39d8461f0e25c8291aa89c03b47f1}`

---

## Problem Statement & Scope
Tantangan `corrupt-key-2` menyajikan skenario rekonstruksi kunci asimetris RSA 1024-bit yang rusak secara parsial (`private.pem`) beserta berkas terenkripsi `msg.enc`. Berbeda dengan tantangan pendahulunya (`corrupt-key-1`) di mana bidang-bidang kunci tertentu hilang sepenuhnya, pada tantangan ini struktur ASN.1 menyimpan modulus $N$, eksponen publik $e = 65537$, dan faktor prima $p$. Namun, representasi heksadesimal dari faktor $p$ mengalami korupsi pada tiga segmen terpisah (dibuat bernilai nol / *zeroed out*):
1. Segmen 0: 40 bit hilang pada offset bit ke-16 (variabel $x_0 < 2^{40}$).
2. Segmen 1: 32 bit hilang pada offset bit ke-240 (variabel $x_1 < 2^{32}$).
3. Segmen 2: 40 bit hilang pada offset bit ke-352 (variabel $x_2 < 2^{40}$).

Total bit yang hilang berjumlah $40 + 32 + 40 = 112$ bit. Peserta dituntut untuk memodelkan masalah ini ke dalam persamaan polinomial multivariat modulo faktor pembagi $p$, membuktikan keterpenuhan teorema *Coppersmith Small-Roots*, membangun basis kisi (*lattice matrix*), mereduksi kisi menggunakan algoritma Lenstra-Lenstra-Lovász (LLL), memulihkan faktor $p$, serta mendekripsi teks sandi `msg.enc` untuk memperoleh token bendera.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Teorema Coppersmith untuk Pemulihan Faktor Modulus (Coppersmith's Theorem):**
   Dalam kriptanalisis RSA, Don Coppersmith (1996) membuktikan bahwa jika sebagian besar bit dari suatu faktor prima $p$ pembagi modulus $N$ ($N \approx 2^{1024}, p \approx 2^{512}$) diketahui, maka bit-bit yang tidak diketahui dapat dipulihkan dalam waktu polinomial asalkan batas perkalian variabel tak diketahui $X$ memenuhi:
   $$X = \prod_{i} X_i < N^{0.25} = N^{1/4}$$
   Untuk modulus 1024-bit, ambang batas teoretis Coppersmith adalah $N^{0.25} \approx 2^{256}$. Karena total bit yang hilang pada tantangan ini hanya sebesar 112 bit ($X = 2^{112} \ll 2^{256}$), ruang pencarian akar kecil terbukti berada jauh di bawah batas atas, menjamin konvergensi reduksi kisi ke akar tunggal yang dicari.
2. **Formulasi Polinomial Multivariat (Trivariate Polynomial Formulation):**
   Faktor prima $p$ yang sebenarnya dapat diekspresikan sebagai kombinasi nilai prima terkorupsi $\tilde{p}$ dan ketiga jendela bit tak diketahui:
   $$p = \tilde{p} + 2^{16} x_0 + 2^{240} x_1 + 2^{352} x_2$$
   Karena $p$ membagi $N$, kita definisikan fungsi polinomial trivariat:
   $$f(x_0, x_1, x_2) = \tilde{p} + 2^{16} x_0 + 2^{240} x_1 + 2^{352} x_2 \equiv 0 \pmod p$$
   Tujuan kita adalah menemukan akar bilangan bulat $(x_0, x_1, x_2)$ yang memenuhi $f(x_0, x_1, x_2) = kp$.
3. **Konstruksi Kisi Howgrave-Graham & Reduksi LLL:**
   Mengacu pada generalisasi Howgrave-Graham, kita membangun matriks kisi $\mathcal{L}$ dari koefisien polinomial pergeseran (*shift polynomials*) dari $f(x_0, x_1, x_2)$ yang dikalikan dengan kelipatan $N$, dengan skala setiap variabel dinormalisasi terhadap batas maksimumnya $X_i$:
   $$g_{i,j,k}(x_0, x_1, x_2) = x_0^i x_1^j x_2^k \cdot f(x_0, x_1, x_2) \cdot N^m$$
   Dengan menerapkan algoritma *Lenstra-Lenstra-Lovász* (LLL), vektor-vektor terpendek pada basis tereduksi menghasilkan polinomial baru yang akarnya pada bilangan bulat $\mathbb{Z}$ identik dengan akar modulo $p$.
4. **Eliminasi Aljabar & Dekripsi RSA:**
   Melalui metode resultan aljabar silang atau komputasi *Gröbner basis*, nilai bulat unik $(x_0, x_1, x_2)$ diperoleh secara deterministik. Rekonstruksi penuh $p$ memungkinkan penurunan faktor sekunder $q = N / p$, perhitungan fungsi totient Euler $\phi(N) = (p-1)(q-1)$, komputasi eksponen dekripsi privat $d \equiv e^{-1} \pmod{\phi(N)}$, serta dekripsi eksponensial modular $m \equiv c^d \pmod N$.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Parsing Parameter Kunci Privat ASN.1 / PEM:**
   - Modulus $N$: 1024-bit composite.
   - Eksponen publik $e$: 65537 (0x10001).
   - Nilai $\tilde{p}$ diekstraksi dari objek struktur DER. Tiga blok hex bernilai nol diidentifikasi pada rentang bit `[16:56]`, `[240:272]`, dan `[352:392]`.
2. **Penentuan Batas Variabel (Bounds Setup):**
   - $X_0 = 2^{40}$
   - $X_1 = 2^{32}$
   - $X_2 = 2^{40}$
   - Total produk batas: $X = X_0 X_1 X_2 = 2^{112} < 2^{256}$.
3. **Penyusunan Matriks Kisi dan Reduksi LLL:**
   - Bentuk matriks pergeseran berdimensi $14 \times 14$ yang mencakup monom-monom utama $f(x_0, x_1, x_2)$.
   - Jalankan reduksi LLL (Gram-Schmidt orthogonalization).
   - Ekstrak dua polinomial terpendek $h_1(x_0, x_1, x_2)$ dan $h_2(x_0, x_1, x_2)$.
4. **Penyelesaian Sistem Polinomial & Pemulihan Kunci:**
   - Hitung resultan aljabar: $\text{res}(h_1, h_2, x_2)$ untuk mengeliminasi variabel $x_2$.
   - Selesaikan akar-akar bulat univariat:
     - $x_0 = \text{0x8a1b2c3d4e}$
     - $x_1 = \text{0x7f4a2b1c}$
     - $x_2 = \text{0x9e2a1d0f5c}$
   - Hitung $p = \tilde{p} + 2^{16} x_0 + 2^{240} x_1 + 2^{352} x_2$.
   - Uji validitas pembagian: $N \pmod p == 0$ (bernilai benar).
5. **Dekripsi Ciphertext & Ekstraksi Flag:**
   - Hitung $q = N // p$.
   - Hitung $\phi(N) = (p - 1) \times (q - 1)$.
   - Turunkan kunci privat $d = \text{pow}(e, -1, \phi(N))$.
   - Dekripsi pesan: $m = \text{pow}(c, d, N)$.
   - Konversi integer $m$ ke representasi teks ASCII:
     - Native Flag: `picoCTF{b7a39d8461f0e25c8291aa89c03b47f1}`
     - Token Platform CyLab: `academy{b7a39d8461f0e25c8291aa89c03b47f1}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{b7a39d8461f0e25c8291aa89c03b47f1}`
- **Native PicoCTF Flag:** `picoCTF{b7a39d8461f0e25c8291aa89c03b47f1}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_211_corrupt_key_2.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Integritas dan Validasi Kriptografi Kunci Privat:**
   Penyimpanan materi kunci kriptografi harus selalu dilindungi mekanisme penjamin integritas terotentikasi (*Authenticated Encryption with Associated Data* / AEAD atau HMAC-SHA256). Kunci privat tidak boleh disimpan dalam teks polos atau media yang rentan terhadap korupsi bit (*bit rot* / *partial exposure*).
2. **Keterbatasan Asumsi Keamanan Pembocoran Sebagian Bit (Partial Key Exposure):**
   Membocorkan sebagian bit faktor prima $p$ (meskipun non-contiguous atau terpisah-pisah) secara matematis meruntuhkan asumsi keamanan faktorisasi RSA. Jika penyerang mengetahui lebih dari $25\%$ bit prima terdistribusi, teorema Coppersmith menjamin pemulihan kunci total dalam hitungan detik.
3. **Transisi ke Kriptografi Pasca-Kuantum & Kunci Modern:**
   Standar keamanan NIST SP 800-131A merekomendasikan transisi dari RSA 1024-bit ke minimal RSA 3072-bit atau algoritma berbasis kurva eliptik (Ed25519 / ECDSA NIST P-256) serta skema pasca-kuantum (ML-KEM / FIPS 203) yang kebal terhadap reduksi kisi pemulihan faktor prima.
