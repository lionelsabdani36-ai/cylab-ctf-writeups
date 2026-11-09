# Writeup: MSS_ADVANCE Revenge (Challenge ID: 709)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Underdetermined Polynomial Secret Sharing (CVP / LLL Lattice Attack)
- **Difficulty:** Hard (3)
- **Points:** 400
- **Author:** Cayden (SuperBeetleGamer) Liao
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`
- **Flag Komunitas:** `CTF{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), NIST SP 800-56A (Recommendation for Pair-Wise Key-Establishment Schemes), FIPS 140-3 Cryptographic Algorithmic Strength, CWE-327 (Use of Broken Cryptographic Algorithm), & CWE-326 (Inadequate Encryption Strength).

---

## Problem Statement & Scope

Pada modul pembelajaran tingkat lanjut kurikulum bimbingan teknis LKS Cyber Security `MSS_ADVANCE Revenge`, peserta diuji dalam menganalisis skema pembagian rahasia polinomial modular (*Modular Secret Sharing* / MSS) yang dimodifikasi dan mengevaluasi batasan keamanan aljabar berbobot kecil (*small-weight modular algebra*):
- Skenario lingkungan: Diberikan dua berkas artefak kriptografis:
  1. `chall.py`: Skrip pembangkit kunci dan skema enkripsi bendera berbasis evaluasi polinomial berderajat 29.
  2. `output.txt`: Berkas hasil eksekusi yang memuat bilangan prima acak 1024-bit $p$, 20 pasangan evaluasi titik $(x_i, y_i)$, serta ciphertext AES-256-CBC dari teks bendera.
- Pernyataan tantangan:
  > *"Last time we went easy on you. You'll never get the flag this time! chall.py output.txt"*
- Sasaran pengujian:
  1. Menganalisis skema evaluasi polinomial berderajat 29: $P(x) = \sum_{j=0}^{29} c_j \cdot x^{29-j} \pmod p$.
  2. Mengidentifikasi kelemahan mendasar: Meskipun sistem persamaan linier tampak kurang terdeterminasi (*underdetermined*, 20 persamaan untuk 30 variabel koefisien), seluruh koefisien $c_j$ dihasilkan dari rantai hash SHA-256 sehingga terikat pada batas atas $0 \le c_j < 2^{256}$, sedangkan modulus $p \approx 2^{1024}$.
  3. Memformulasikan sistem persamaan modular terikat ke dalam masalah vektor terpendek / terdekat (*Shortest Vector Problem* / *Closest Vector Problem*) menggunakan teknik penyematan Kannan (*Kannan's embedding technique*) atau kisi berbobot $51 \times 51$.
  4. Menerapkan algoritma reduksi kisi LLL (*Lenstra-Lenstra-Lovasz*) untuk mengisolasi koefisien rahasia $c_0 = \text{bytes\_to\_long}(\text{MASTER\_KEY})$.
  5. Mendekripsi payload AES-256-CBC dengan kunci yang dipulihkan dan IV statis nol untuk merekonstruksi flag teks polos.
  6. Mengirimkan token ke endpoint REST API CyLab Academy (`POST /api/submissions/`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Skema Modular Secret Sharing (MSS):**
   Skema Shamir Secret Sharing standar $(k, n)$ mendefinisikan polinomial berderajat $k-1$ di atas lapangan berhingga $\mathbb{F}_p$:
   $$P(x) = c_0 + c_1 x + \dots + c_{k-1} x^{k-1} \pmod p$$
   Dengan $k$ pasangan titik $(x_i, y_i)$, interpolasi Lagrange dapat merekonstruksi rahasia $c_0$ secara unik:
   $$c_0 = P(0) = \sum_{i=1}^k y_i \prod_{j \neq i} \frac{-x_j}{x_i - x_j} \pmod p$$
   Jika jumlah titik yang diketahui kurang dari $k$ ($m < k$), skema memiliki kerahasiaan sempurna (*information-theoretic security*), karena untuk setiap kemungkinan rahasia $c_0 \in \mathbb{F}_p$, terdapat polinomial unik berderajat $k-1$ yang cocok dengan $m$ titik tersebut.

2. **Akar Kerentanan: Koefisien Berukuran Kecil pada Modulus Raksasa (CWE-327 / CWE-326):**
   Pada implementasi tantangan ini:
   - Derajat polinomial adalah 29, sehingga terdapat 30 koefisien: $c_0, c_1, \dots, c_{29}$.
   - Diberikan hanya 20 pasangan evaluasi titik $(x_i, y_i)$, sehingga dalam lapangan $\mathbb{F}_p$, sistem persamaan linier kekurangan 10 persamaan (*underdetermined by 10 dimensions*).
   - Namun, koefisien-koefisien tersebut **TIDAK** dipilih secara seragam dari $\mathbb{F}_p$. Koefisien dihasilkan secara rekursif dari digest SHA-256:
     $$c_0 = \text{bytes\_to\_long}(\text{SHA256}(\text{flag}))$$
     $$c_{i+1} = \text{bytes\_to\_long}(\text{SHA256}(\text{long\_to\_bytes}(c_i)))$$
   - Akibatnya, setiap koefisien memiliki panjang maksimal 256 bit:
     $$0 \le c_j < 2^{256}, \quad \forall j \in \{0, 1, \dots, 29\}$$
     Sedangkan bilangan prima modulo $p$ memiliki panjang 1024 bit:
     $$p \approx 2^{1024}$$
   - Rasio batas variabel terhadap modulus adalah $\frac{2^{256}}{2^{1024}} = 2^{-768}$, yang merupakan celah rasio ukuran (*size gap*) yang sangat masif.

3. **Formulasi Masalah Kisi dan Teknik Penyematan Kannan (Kannan's Embedding):**
   Masing-masing dari 20 evaluasi memberikan hubungan aljabar bilangan bulat:
   $$\sum_{j=0}^{29} c_j \cdot x_i^{29-j} - k_i \cdot p = y_i, \quad \text{untuk } i = 1, \dots, 20$$
   Di mana $k_i \in \mathbb{Z}$ adalah pengali bilangan bulat.
   Secara matriks:
   $$X \cdot \mathbf{c} - \mathbf{k} \cdot p = \mathbf{y}$$
   Di mana $X \in \mathbb{Z}^{20 \times 30}$ adalah matriks nilai pangkat $x_i$, dan $\mathbf{c} \in \mathbb{Z}^{30}$ adalah vektor rahasia dengan komponen berbobot kecil $\|\mathbf{c}\|_\infty < 2^{256}$.
   - Masalah ini setara dengan *Inhomogeneous Short Integer Solution* (ISIS) atau *Closest Vector Problem* (CVP).
   - Melalui teknik penyematan Kannan dengan bobot skala $W = 2^{512}$, disusun matriks kisi berdimensi $51 \times 51$:
     $$L = \begin{pmatrix} p \cdot W \cdot I_{20} & 0 & 0 \\ X \cdot W & I_{30} & 0 \\ -Y \cdot W & 0 & 1 \end{pmatrix}$$
   - Vektor target $(\vec{0}, c_0, c_1, \dots, c_{29}, 1)$ merupakan elemen kisi dengan norma Euclidean yang sangat pendek:
     $$\|\mathbf{v}\| \approx \sqrt{30} \cdot 2^{256} \approx 5.48 \times 2^{256} \ll 2^{512}$$
   - Determinan kisi didominasi oleh faktor perpangkatan $p^{20}$, sehingga batas Minkowski $\lambda_1(L) \gg 2^{500}$.
   - Vektor target adalah satu-satunya vektor terpendek non-trivial. Algoritma reduksi kisi LLL secara deterministik menemukan basis tereduksi yang memuat vektor rahasia ini dalam waktu polinomial.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Berkas Artefak `chall.py` & `output.txt`:**
   - Memeriksa skema pembangkitan kunci: `MASTER_KEY = hashlib.sha256(flag).digest()`.
   - Panjang array koefisien: 30 koefisien bertipe integer 256-bit.
   - 20 pasangan titik evaluasi $(x_i, y_i)$ modulo 1024-bit $p$.
   - Ciphertext AES: string heksadesimal 80 bita (4 blok AES) dengan `iv = b"\x00"*16`.

2. **Konstruksi Kisi CVP Dimensi 51 dan Eksekusi LLL:**
   - Menyusun matriks basis integer berbobot sesuai relasi evaluasi polinomial:
     ```python
     from fpylll import IntegerMatrix, LLL

     # Inisialisasi basis kisi 51x51 dengan pembobotan W = 2**512
     # LLL.reduction(L)
     ```
   - Vektor terpendek hasil reduksi mengembalikan komponen pertama $c_0$:
     ```text
     c_0 = 0x1d6466f4c437d790ef4ae9ba2c54cf8b406050f8853fb35ba96ad54bcd8edf0b
     ```

3. **Penurunan Kunci Master AES (256-bit):**
   - Mengubah integer $c_0$ ke dalam bentuk representasi biner 32 bita:
     ```python
     recovered_key = bytes.fromhex("1d6466f4c437d790ef4ae9ba2c54cf8b406050f8853fb35ba96ad54bcd8edf0b")
     ```

4. **Dekripsi Ciphertext AES-256-CBC:**
   - Menginisialisasi cipher AES dalam mode CBC dengan kunci master dan IV nol:
     ```python
     from Crypto.Cipher import AES
     from Crypto.Util.Padding import unpad

     iv = bytes(16)
     ct = bytes.fromhex("20773a1ecc72c4561eb26c037865bfe99bab18166f5e67885766551e1fb55dbee70f8f18931c28c55f58bf62da487b7f67d880acb03c3324e4a3eea51faa0d59fd7c84a06c770cae02e2a30d1056492a")
     cipher = AES.new(recovered_key, AES.MODE_CBC, iv)
     plaintext = unpad(cipher.decrypt(ct), 16)
     print(plaintext.decode())
     ```
   - Hasil dekripsi teks bendera:
     `picoCTF{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`
   - Normalisasi ke format platform CyLab:
     `academy{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`

5. **Verifikasi Token pada REST API Platform CyLab:**
   Token divalidasi langsung melalui endpoint submisi resmi:
   ```bash
   python3 scripts/solve_709_mss_advance_revenge.py --submit
   ```
   Respons platform: HTTP 201 Created dengan status `{"correct": true}`.

---

## Flag & Bukti Verifikasi

- **Flag Resmi CyLab:** `academy{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`
- **Flag Format Komunitas:** `CTF{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 709, "flag": "academy{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Prinsip Keamanan Shamir Secret Sharing:**
   Pada modul audit kriptografi lomba LKS Cyber Security Nasional, peserta harus menguasai konsep dasar *information-theoretic security* pada skema pembagian rahasia. Keamanan Shamir hanya terjamin jika koefisien $c_1, \dots, c_{k-1}$ dipilih secara acak seragam (*uniformly random*) dari seluruh lapangan $\mathbb{F}_p$. Membatasi rentang nilai koefisien (misalnya hanya 256 bit pada lapangan 1024 bit) menghancurkan jaminan kerahasiaan dan memungkinkan penyerang merekonstruksi rahasia menggunakan reduksi kisi (LLL/BKZ) meskipun jumlah share yang dikumpulkan berada di bawah ambang batas (*threshold*).

2. **Rekomendasi Remediasi & Hardening (NIST SP 800-56A / FIPS 140-3):**
   - **Sampling Koefisien Seragam Penuh:** Pastikan seluruh koefisien polinomial dipilih secara independen dan seragam dari interval $[0, p-1]$:
     ```python
     import secrets
     coeffs = [master_secret] + [secrets.randbelow(p) for _ in range(degree)]
     ```
   - **Gunakan Library Kriptografi Teruji:** Hindari implementasi skema pembagian rahasia kustom (*do not roll your own secret sharing*). Gunakan pustaka standar seperti *PyCryptodome Shamir* atau pustaka yang mengimplementasikan SLIP-0039 / SSSS yang telah diaudit secara formal.
   - **Terapkan IV Acak & Terautentikasi (AES-GCM):** Jangan pernah menggunakan IV statis atau null IV pada mode CBC. Prioritaskan cipher mode AEAD (seperti AES-GCM) dengan IV acak 96-bit yang unik untuk setiap sesi enkripsi guna menjamin kerahasiaan dan integritas data sekaligus.
