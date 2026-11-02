# Writeup: Sequences (Challenge ID: 297)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography
- **Difficulty:** Medium (2)
- **Author:** CyLab Team
- **Event:** picoCTF 2022
- **Points:** 400
- **Flag:** `academy{b1g_numb3rs_56b2970a}`

---

## Deskripsi Tantangan
> I wrote this linear recurrence function, can you figure out how to make it run fast enough and get the flag?
> Download the code artifact `sequences.py`.
>
> Target komputasi: $m(2 \times 10^7) \pmod{10^{10000}}$.
> Verifikasi: Hash MD5 dari representasi string hasil harus cocok dengan `96cc5f3b460732b442814fd33cf8537c`, lalu digunakan sebagai kunci SHA256 untuk mendekripsi ciphertext flag.
>
> Hints:
> 1. Google "matrix diagonalization". Can you figure out how to apply it to this function?

---

## Analisis Kerentanan & Konsep Teknis (Root Cause Theory)
1. **Bottleneck Algoritmik Rekursi Linier:**
   - Relasi rekurensi linier orde-4 didefinisikan sebagai:
     $$m(i) = 21 m(i-1) + 301 m(i-2) - 9549 m(i-3) + 55692 m(i-4)$$
     dengan kondisi batas $m(0)=1, m(1)=2, m(2)=3, m(3)=4$.
   - Pendekatan rekursif naif dengan `@functools.cache` atau iteratif linear membutuhkan $2 \times 10^7$ langkah perkalian bilangan ribuan digit, yang menyebabkan *stack overflow* atau kehabisan memori (*out-of-memory*).
2. **Polinomial Karakteristik & Akar Integer:**
   - Persamaan karakteristik dari relasi rekursif tersebut adalah:
     $$\lambda^4 - 21\lambda^3 - 301\lambda^2 + 9549\lambda - 55692 = 0$$
   - Melalui faktorisasi aljabar:
     $$(\lambda - 17)(\lambda - 13)(\lambda - 12)(\lambda + 21) = 0$$
   - Ditemukan 4 akar real bulat berbeda: $\lambda_1 = -21, \lambda_2 = 12, \lambda_3 = 13, \lambda_4 = 17$.
3. **Bentuk Tertutup (Closed-Form Solution):**
   - Solusi umum berbentuk kombinasi linear dari pangkat akar karakteristik:
     $$m(i) = c_1 (-21)^i + c_2 (12)^i + c_3 (13)^i + c_4 (17)^i$$
   - Dengan menyelesaikan sistem persamaan linear matriks Vandermonde untuk $i \in \{0, 1, 2, 3\}$:
     $$c_1 = \frac{403}{10659} = \frac{1612}{42636}$$
     $$c_2 = \frac{760}{33} = \frac{981920}{42636}$$
     $$c_3 = -\frac{1727}{68} = -\frac{1082829}{42636}$$
     $$c_4 = \frac{253}{76} = \frac{141933}{42636}$$
   - Kelipatan persekutuan terkecil penyebut adalah $D = 42636$.
4. **Eksponensiasi Modular Cepat $O(\log N)$:**
   - Kita hanya membutuhkan hasil akhir modulo $10^{10000}$.
   - Modulus komposit yang digunakan adalah $M = 10^{10000} \times 42636$.
   - Masing-masing suku $\lambda_k^{ITERS} \pmod M$ dapat dihitung secara instan menggunakan fungsi bawaan `pow(base, exp, mod)` dalam waktu $<0.1$ detik.
   - Hasil bagi bulat $(S // 42636) \pmod{10^{10000}}$ menghasilkan solusi eksak yang memenuhi verifikasi MD5.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Penentuan Akar Karakteristik:**
   - Menyusun polinomial matriks transisi dari relasi rekurensi dan menyelesaikan akar-akar eigennya.
2. **Kalkulasi Bobot Koefisien $c_k$:**
   - Menginversi matriks Vandermonde $4 \times 4$ terhadap vektor inisial $[1, 2, 3, 4]^T$.
   - Normalisasi seluruh pecahan ke penyebut bersama $D = 42636$.
3. **Evaluasi Modular Skala Besar:**
   - Menetapkan batas digit integer Python via `sys.set_int_max_str_digits(25000)`.
   - Mengalikan masing-masing basis dengan eksponen $2 \times 10^7$ modulo $M = 10^{10000} \times 42636$.
   - Menjumlahkan seluruh suku dan membagi dengan $D$.
4. **Verifikasi Hash & Dekripsi XOR:**
   - Menghitung digest MD5 dari representasi string hasil solusi, mencocokkannya dengan `VERIF_KEY`.
   - Melakukan hash SHA256 dari string solusi untuk menghasilkan keystream 32-byte.
   - Melakukan operasi XOR antara `ENCRYPTED_FLAG` dan keystream SHA256 untuk memulihkan plaintext flag.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{b1g_numb3rs_56b2970a}`
- **Bukti Validasi REST API:**
  - Metode: `POST /api/submissions/`
  - Payload: `{"challenge": 297, "flag": "academy{b1g_numb3rs_56b2970a}"}`
  - Respons: `HTTP 201 Created` — `{"user": 1072359, "challenge": 297, "flag": "academy{...}", "correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Efisiensi Komputasi Algoritmik:**
   - Dalam kompetensi LKS Cyber Security, evaluasi performa algoritma kriptografis sangat krusial. Sistem kriptografi yang mengimplementasikan operasi modular atau deret rekursif tanpa optimasi matematika dapat dieksploitasi melalui *Denial of Service (DoS)* berbasis konsumsi sumber daya CPU/memori.
2. **Rekomendasi Remediasi / Hardening:**
   - Jika suatu fungsi bisnis memerlukan deret linier berulang, gunakan closed-form solution atau representasi matriks perpangkatan biner (*binary matrix exponentiation*) $O(k^3 \log N)$ daripada rekursi bertingkat.
   - Batasi input iterasi pengguna (*input bounds validation*) pada parameter kalkulasi matematika untuk mencegah serangan ReDoS atau algorithmic complexity exhaustion.
