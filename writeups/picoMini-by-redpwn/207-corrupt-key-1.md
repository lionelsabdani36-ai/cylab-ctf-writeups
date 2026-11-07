# Writeup: corrupt-key-1 (Challenge ID: 207)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Partial Prime Leakage & Coppersmith Small-Roots Lattice Reduction (CWE-326 / CWE-327)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 350
- **Author:** Tux
- **Flag:** `academy{d741543f172970457e6a9aaa890935b8}`

---

## Problem Statement & Scope
Tantangan `corrupt-key-1` menyajikan skenario forensik kriptografi di mana peserta diberikan dua berkas: sebuah berkas kunci privat RSA format PEM yang mengalami kerusakan parsial (*corrupted private key*), dan sebuah berkas ciphertext biner berukuran 128 byte bernama `msg.enc`. 

Saat dianalisis menggunakan utilitas pengurai struktur ASN.1 (`openssl asn1parse`), struktur kunci privat masih memuat modulus publik $n$ (1024-bit), eksponen publik $e = 65537$, serta 256 bit paling signifikan (*upper 256 bits*) dari salah satu bilangan prima pembentuknya, yaitu $p$ (`p_high`). Namun, 256 bit terbawah dari $p$, seluruh bit dari prima $q$, eksponen dekripsi $d$, serta koefisien Chinese Remainder Theorem (CRT) telah hilang atau ditimpa byte nol. Peserta ditugaskan merekonstruksi nilai faktor prima $p$ secara penuh dari informasi bit parsial yang ada, menghitung ulang kunci privat RSA, dan mendekripsi berkas `msg.enc` untuk memperoleh flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kegagalan Total Keamanan RSA Akibat Kebocoran Parsial Faktor Prima (CWE-326):**
   Keamanan algoritma RSA bertumpu pada kesulitan komputasi pemfaktoran bilangan bulat besar $n = p \times q$ jika kedua faktor prima dirahasiakan sepenuhnya. Namun, jika sebagian bit dari salah satu faktor prima bocor ke publik, sistem rentan terhadap serangan reduksi kisi (*lattice reduction attack*).
2. **Teorema Coppersmith untuk Pencarian Akar Polinomial Kecil (Coppersmith's Small Roots):**
   Pada tahun 1996, Donald Coppersmith membuktikan bahwa akar bilangan bulat kecil $x_0$ dari polinomial univariat monik $f(x) \equiv 0 \pmod p$ dapat ditemukan dalam waktu polinomial (*polynomial time*) menggunakan algoritma reduksi basis kisi Lenstra-Lenstra-Lovász (LLL), asalkan batas atas akar memenuhi:
   $$|x_0| < n^{\beta^2 / d}$$
   di mana $p$ adalah pembagi dari $n$ dengan ukuran $p \ge n^\beta$, dan $d$ adalah derajat polinomial.
3. **Formulasi Polinomial & Kondisi Batas Howgrave-Graham:**
   Karena $p \approx n^{0.5}$ (untuk modulus seimbang 1024-bit, $p$ berukuran 512 bit), dan kita mengetahui 256 bit teratas dari $p$ ($p_{high}$), prima $p$ dapat diekspresikan sebagai:
   $$p = p_{high} \cdot 2^{256} + x_0$$
   dengan $x_0 < 2^{256} \approx n^{0.25}$.
   Mendefinisikan polinomial:
   $$f(x) = p_{high} \cdot 2^{256} + x$$
   Karena $x_0 < n^{0.25}$, kondisi batas Coppersmith untuk pemfaktoran dengan informasi bit tinggi terpenuhi secara sempurna ($\beta = 0.5 \implies \beta^2 = 0.25$).
4. **Reduksi Kisi Howgrave-Graham (LLL Basis Reduction):**
   Dengan membangun matriks kisi berdimensi $m$ yang dibentangkan oleh kombinasi linier dari polinomial $g_{i,j}(x) = x^j \cdot n^{m-i} \cdot f(x)^i$ dan menerapkan algoritma LLL, kita menghasilkan polinomial baru dengan koefisien bilangan bulat kecil yang memiliki akar $x_0$ yang sama persis di atas lapangan bilangan real $\mathbb{R}$. Mencari akar di atas $\mathbb{R}$ dilakukan secara deterministik tanpa perlu memfaktorkan modulo $n$.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Parameter dari Berkas Kunci Rusak:**
   Menggunakan pustaka `pycryptodome` dan parser ASN.1, diekstraksi nilai integer:
   - Modulus $n$ (1024-bit integer heksadesimal `0x00b8cb1c...024f`).
   - Eksponen publik $e = 65537$.
   - Komponen bit tinggi $p_{high}$ (256-bit `0xe700568f...3d4f`).
2. **Penerapan Algoritma Coppersmith via SageMath / LLL:**
   Memformulasikan cincin polinomial modulo $n$:
   ```python
   PR.<x> = PolynomialRing(Zmod(n))
   f = p_high * 2^256 + x
   # Melakukan pencarian akar kecil dengan batas X = 2^256 dan beta = 0.45
   roots = f.small_roots(X=2^256, beta=0.45)
   ```
   Algoritma LLL mengonvergensi kisi dan menemukan akar bulat $x_0$:
   $$p = p_{high} \cdot 2^{256} + x_0$$
   Nilai prima $p$ yang dipulihkan:
   `12098520864598198757294135341465388062087431109285224283440314414683283061468500249596026217234382854875647811812632201834942205849073893715844547051090363`.
3. **Verifikasi Pemfaktoran dan Pembentukan Kunci:**
   - Evaluasi $n \pmod p == 0$ (terbukti habis dibagi tanpa sisa).
   - Menghitung $q = n // p$.
   - Menghitung fungsi totient Euler: $\phi(n) = (p - 1)(q - 1)$.
   - Menghitung eksponen privat: $d = e^{-1} \pmod{\phi(n)}$.
4. **Dekripsi Ciphertext `msg.enc`:**
   Membaca 128 byte ciphertext sebagai integer $c$:
   $$m = c^d \pmod n$$
   Mengonversi integer $m$ kembali menjadi byte string ASCII menghasilkan blok padding PKCS#1 v1.5 dengan payload akhir:
   `Here is your flag: picoCTF{d741543f172970457e6a9aaa890935b8}`.
5. **Normalisasi Token CyLab Academy:**
   Token dinormalisasi sesuai standar kompetisi: `academy{d741543f172970457e6a9aaa890935b8}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{d741543f172970457e6a9aaa890935b8}`
- **Native PicoCTF Flag:** `picoCTF{d741543f172970457e6a9aaa890935b8}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_207_corrupt_key_1.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Perlindungan Integritas Kunci Kriptografis (Cryptographic Key Lifecycle Security):**
   Kunci privat tidak boleh disimpan dalam media yang rentan terhadap modifikasi atau kerusakan parsial. Kerusakan parsial (bit rot atau memory tampering) yang mengekspos separuh bit prima sudah cukup untuk meruntuhkan seluruh arsitektur keamanan kriptosistem asimetris.
2. **Penyimpanan Kunci Terenkripsi dalam Hardware Security Module (HSM / TPM):**
   Kunci privat harus dibuat, disimpan, dan dieksekusi di dalam modul perangkat keras tersertifikasi (FIPS 140-3 Level 3 / Common Criteria EAL4+) seperti HSM atau TPM, di mana material kunci mentah tidak pernah diekspos ke memori aplikasi atau sistem berkas publik.
3. **Pemberlakuan Verifikasi Integritas Asimetris Sebelum Operasi Dekripsi:**
   Aplikasi yang mengelola berkas kunci privat ASN.1/DER wajib melakukan pengecekan konsistensi matematis yang ketat saat inisialisasi:
   - Pastikan $p \times q == n$.
   - Pastikan $(e \times d) \equiv 1 \pmod{\text{LCM}(p-1, q-1)}$.
   Jika terdapat inkonsistensi atau bidang data yang bernilai nol secara mencurigakan, kunci harus segera ditolak dan dicabut (*revocation*).
