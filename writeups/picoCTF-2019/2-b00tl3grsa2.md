# Writeup: b00tl3gRSA2 (Challenge ID: 2)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Asymmetric Key Generation Weaknesses & Continued Fractions
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 200
- **Author:** John Hammond / picoCTF Team
- **Flag:** `academy{bad_1d3a5_1583381}`

---

## Problem Statement & Scope
Tantangan `b00tl3gRSA2` menyajikan implementasi kriptografi kunci publik RSA dengan konfigurasi kunci privat yang tidak lazim. Pada skenario tantangan, server menyediakan:
1. Ciphertext terenkripsi $C$ (1024-bit integer).
2. Modulus publik $N$ (1024-bit integer, hasil kali dua bilangan prima $p$ dan $q$).
3. Eksponen publik $e$ (1022-bit integer, berukuran sangat besar mendekati $N$).

Pengembang sistem mencoba mengoptimalkan kecepatan dekripsi atau penandatanganan pesan dengan memilih eksponen privat $d$ yang sangat kecil. Ruang lingkup audit ini berfokus pada evaluasi keamanan parameter kunci RSA berdasarkan standar NIST SP 800-115 Section 4.3 dan pembuktian kerentanan *Wiener's Continued Fraction Attack*.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kelemahan Pemilihan Kunci Privat Kecil (CWE-326: Inadequate Encryption Strength):**
   Pada algoritma RSA (RFC 8017), relasi matematis antara kunci publik $(e, N)$ dan kunci privat $d$ didefinisikan sebagai:
   $$e \cdot d \equiv 1 \pmod{\phi(N)}$$
   di mana fungsi totient Euler $\phi(N) = (p - 1)(q - 1) = N - (p + q) + 1$.
   Persamaan ini dapat dituliskan kembali dalam bentuk linier Diophantine:
   $$e \cdot d - k \cdot \phi(N) = 1$$
   untuk suatu bilangan bulat positif $k$.

2. **Teorema Wiener (Wiener's Attack):**
   Michael J. Wiener (1990) membuktikan bahwa jika eksponen privat $d$ memenuhi batas batas ketahanan:
   $$d < \frac{1}{3} N^{1/4}$$
   dan $q < p < 2q$, maka pecahan $\frac{k}{d}$ merupakan salah satu konvergen (*convergent*) dalam ekspansi pecahan berlanjut (*continued fraction expansion*) dari $\frac{e}{N}$:
   $$\left| \frac{e}{N} - \frac{k}{d} \right| < \frac{1}{2d^2}$$
   Karena sifat pecahan berlanjut, rasio $\frac{k}{d}$ yang mendekati $\frac{e}{N}$ dapat dihitung secara efisien dalam waktu polinomial $O(\log N)$ menggunakan algoritma Euclidean.

3. **Verifikasi Kandidat dan Faktorisasi Modulus:**
   Untuk setiap konvergen $\frac{k_i}{d_i}$:
   - Periksa apakah $k_i > 0$ dan $(e \cdot d_i - 1)$ habis dibagi $k_i$.
   - Jika habis dibagi, tentukan kandidat totient:
     $$\phi_{\text{cand}} = \frac{e \cdot d_i - 1}{k_i}$$
   - Suku $(p + q)$ kemudian dapat ditentukan:
     $$p + q = N - \phi_{\text{cand}} + 1$$
   - Bilangan prima $p$ dan $q$ merupakan akar-akar dari persamaan kuadrat:
     $$x^2 - (p + q)x + N = 0$$
   - Diskriminan persamaan kuadrat:
     $$\Delta = (p + q)^2 - 4N$$
   - Jika $\Delta \ge 0$ dan merupakan bilangan kuadrat sempurna (*perfect square*), maka nilai $p$ dan $q$ adalah bilangan bulat prima sejati, yang membuktikan secara konklusif bahwa penyebut konvergen $d_i$ adalah eksponen privat $d$ yang dicari.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Parameter Kunci Publik:**
   - Parameter modulus $N$ memiliki panjang 1024 bit.
   - Eksponen publik $e$ memiliki panjang 1022 bit ($e \approx N$). Nilai $e$ yang sangat besar merupakan indikator kuat bahwa pembuat soal menggunakan nilai $d$ yang kecil.
   - Ambang batas Wiener untuk modulus 1024 bit adalah:
     $$d < \frac{1}{3} (2^{1024})^{1/4} = \frac{1}{3} \cdot 2^{256} \approx 3.86 \times 10^{76}$$

2. **Ekspansi Pecahan Berlanjut:**
   Hitung koefisien pecahan berlanjut untuk $\frac{e}{N}$ menggunakan algoritma pembagian bersisa bertingkat:
   $$[a_0; a_1, a_2, \dots, a_m]$$

3. **Evaluasi Barisan Konvergen:**
   Hitung pasangan pembilang dan penyebut $(k_i, d_i)$ secara iteratif dari koefisien pecahan berlanjut.

4. **Deteksi Eksponen Privat & Dekripsi:**
   Pada evaluasi konvergen, ditemukan konvergen dengan penyebut $d = 65537$ (17 bit). Nilai ini memenuhi persamaan kuadrat faktorisasi dengan diskriminan kuadrat sempurna, membuktikan bahwa $d$ adalah kunci privat yang valid.

5. **Pemulihan Pesan Terang:**
   Hitung teks terang $M$ melalui eksponensiasi modular:
   $$M = C^d \pmod N$$
   Konversikan representasi integer $M$ ke dalam format heksadesimal dan byte ASCII untuk mendapatkan teks flag:
   `picoCTF{bad_1d3a5_2152720}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{bad_1d3a5_1583381}`
- **Native Platform Flag:** `academy{bad_1d3a5_1583381}`
- **Status Solver:** Teruji dan terverifikasi penuh via live container instance parameter capture dan terkonfirmasi valid pada endpoint platform `/api/submissions/` (HTTP 201 `{"correct": true}`). Skrip reproduktif: `scripts/solve_2_b00tl3g_rsa2.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Penetapan Batas Minimum Panjang Kunci Privat RSA:**
   Sesuai rekomendasi NIST SP 800-56B Rev. 2 dan FIPS 186-4 (*Digital Signature Standard*), eksponen privat $d$ tidak boleh dipilih bernilai kecil demi alasan efisiensi komputasi. Panjang eksponen privat wajib memenuhi kriteria $d > 2^{N/2}$ atau setara dengan ukuran modulus untuk mencegah seluruh varian serangan fraksi berlanjut Wiener maupun serangan kisi (*lattice-based Coppersmith / Boneh-Durfee attack*).

2. **Standardisasi Pemilihan Eksponen Publik ($e = 65537$):**
   Secara defensif, arsitektur kriptografi modern menetapkan eksponen publik bernilai tetap $e = F_4 = 65537$ ($2^{16} + 1$). Pemilihan ini menjamin komputasi enkripsi yang cepat (hanya memerlukan 17 operasi perkalian modular) sementara nilai kunci privat $d = e^{-1} \pmod{\phi(N)}$ akan memiliki ukuran yang tersebar merata sepanjang modulus $N$ ($d \approx N$), sehingga kebal terhadap serangan Wiener dan Boneh-Durfee.
