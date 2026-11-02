# Writeup: Sum-O-Primes (Challenge ID: 310)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography
- **Difficulty:** Medium (2)
- **Author:** CyLab Team
- **Event:** picoCTF 2022
- **Points:** 400
- **Flag:** `academy{pl33z_n0_g1v3_c0ngru3nc3_0f_5qu4r35_b18bb8b6}`

---

## Deskripsi Tantangan
> We have so much faith in RSA we give you not just the product of the primes, but their sum as well!
> Download the artifacts:
> - `gen.py`: Generator skrip pembentuk kunci RSA dan enkripsi flag.
> - `output.txt`: Berisi representasi heksadesimal dari $x = p + q$, modulus $n = p \times q$, dan ciphertext $c$.
>
> Hint:
> 1. I love squares :)

---

## Analisis Kerentanan & Konsep Teknis (Root Cause Theory)
1. **Dasar Keamanan Kriptografi RSA:**
   - Keamanan asimetris RSA bertumpu pada kesulitan komputasi faktorisasi bilangan bulat besar (*integer factorization problem*). Diberikan modulus publik $n = p \times q$ dengan $p, q$ bilangan prima berukuran besar (misal 1024-bit), menemukan $p$ dan $q$ tanpa informasi tambahan adalah infeasible secara komputasional.
2. **Kebocoran Parameter Tambahan ($p + q$):**
   - Pada tantangan ini, penyerang tidak hanya diberikan modulus $n = p \times q$, tetapi juga penjumlahan eksplisit dari kedua faktor prima $x = p + q$.
   - Kedua bilangan prima $p$ dan $q$ merupakan akar-akar dari polinomial kuadrat derajat 2:
     $$(t - p)(t - q) = t^2 - (p + q)t + pq = t^2 - x \cdot t + n = 0$$
3. **Mekanisme Faktorisasi Deterministik (Vieta's Formulas & Quadratic Discriminant):**
   - Diskriminan dari persamaan kuadrat tersebut adalah:
     $$\Delta = b^2 - 4ac = x^2 - 4n = (p + q)^2 - 4pq = (p - q)^2$$
   - Karena $p$ dan $q$ adalah bilangan bulat, selisih kuadrat $(p - q)^2$ merupakan kuadrat sempurna (*perfect square*).
   - Nilai akar diskriminan $\sqrt{\Delta} = |p - q|$ dapat dihitung secara instan menggunakan algoritma integer square root (`math.isqrt`).
   - Dengan sistem persamaan linear dua variabel:
     $$p = \frac{x + \sqrt{\Delta}}{2}, \quad q = \frac{x - \sqrt{\Delta}}{2}$$
   - Setelah $p$ dan $q$ terfaktorkan secara trivial, fungsi totient Euler $\phi(n) = (p - 1)(q - 1)$ dapat dihitung, diikuti oleh kunci privat $d = e^{-1} \pmod{\phi(n)}$, sehingga ciphertext $c$ dapat didekripsi sempurna.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Parameter dari `output.txt`:**
   - Membaca dan mengonversi nilai hex $x$, $n$, dan $c$ ke dalam integer Python berpresisi tinggi.
   - Nilai eksponen publik standar $e = 65537$ (`0x10001`).
2. **Kalkulasi Diskriminan & Akar Kuadrat Bulat:**
   - Menghitung $\Delta = x^2 - 4n$.
   - Menjalankan `sqrt_delta = math.isqrt(delta)` dan melakukan asersi validasi $\text{sqrt\_delta}^2 == \Delta$.
3. **Rekonstruksi Faktor Prima $p$ dan $q$:**
   - Menghitung $p = (x + \text{sqrt\_delta}) // 2$ dan $q = (x - \text{sqrt\_delta}) // 2$.
   - Memastikan kebenaran faktorisasi dengan asersi $p \times q == n$.
4. **Derivasi Kunci Privat & Dekripsi:**
   - Menghitung totient $\phi(n) = (p - 1) \times (q - 1)$.
   - Menghitung kunci privat $d = \text{pow}(e, -1, \phi)$.
   - Menghitung plain message integer $m = \text{pow}(c, d, n)$.
   - Mengonversi integer $m$ ke byte string ASCII untuk mendapatkan flag.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{pl33z_n0_g1v3_c0ngru3nc3_0f_5qu4r35_b18bb8b6}`
- **Bukti Validasi REST API:**
  - Metode: `POST /api/submissions/`
  - Payload: `{"challenge": 310, "flag": "academy{pl33z_n0_g1v3_c0ngru3nc3_0f_5qu4r35_b18bb8b6}"}`
  - Respons: `HTTP 201 Created` — `{"user": 1072359, "challenge": 310, "flag": "academy{...}", "correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Kebocoran Informasi Kriptografis (Information Leakage):**
   - Dalam kompetensi LKS Cyber Security bidang Kriptografi Defensif, peserta harus memahami bahwa parameter pembentuk kunci rahasia tidak boleh bocor secara langsung maupun turunan aljabarnya. Mengetahui relasi linear sederhana antara $p$ dan $q$ mendegradasi kompleksitas serangan dari sub-eksponensial (General Number Field Sieve) menjadi $O(1)$ polinomial instan.
2. **Rekomendasi Remediasi / Hardening:**
   - Modulus publik $n$ dan eksponen $e$ adalah satu-satunya nilai yang diizinkan untuk dipublikasikan dalam arsitektur PKI (Public Key Infrastructure).
   - Komponen internal seperti $p, q, \phi(n), d$, dan intermediate values harus dimusnahkan secara aman dari memori (*zeroization*) setelah proses pembangkitan pasangan kunci selesai.
   - Gunakan pustaka kriptografi terstandarisasi FIPS 140-3 / OpenSSL untuk key generation dan manajemen sertifikat daripada implementasi generator kustom yang rentan *side-channel leakage*.
