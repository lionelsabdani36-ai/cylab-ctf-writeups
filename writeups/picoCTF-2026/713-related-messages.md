# Writeup: Related Messages (Challenge ID: 713)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Franklin-Reiter Related Message Attack over Unpadded RSA
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** CyLab Academy / picoCTF
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{m3ssage_w1th_typ0}`
- **Flag Komunitas:** `CTF{m3ssage_w1th_typ0}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 8017 (PKCS #1 v2.2: RSA Cryptography Specifications), NIST SP 800-56B Rev. 2 (Recommendation for Pair-Wise Key-Establishment Schemes: Padding & Encryption Integrity), & CWE-327 (Use of a Broken or Risky Cryptographic Algorithm - Unpadded Textbook RSA with Small Exponent e=17).

---

## Problem Statement & Scope

Pada modul bimbingan teknis persiapan lomba LKS `Related Messages`, peserta diuji dalam menganalisis integritas implementasi algoritma kriptografi asimetris RSA deterministik (tanpa skema padding acak) ketika dua pesan yang memiliki relasi afinitas linier dienkripsi menggunakan modulus dan eksponen publik yang sama:
- Skenario lingkungan: Diberikan dua berkas artefak kriptografis:
  1. Skrip enkripsi Python: `chall.py`.
  2. Berkas keluaran ciphertext: `output.txt` yang memuat dua nilai ciphertext ($c_1, c_2$), selisih integer antara kedua pesan asli ($\Delta = m_1 - m_2 = -3$), dan modulus RSA 2048-bit $N$.
- Pernyataan tantangan:
  > *"Oops! I have a typo in my first message so i sent it again! I used RSA twice so this is secure right?"*
- Sasaran pengujian:
  1. Menganalisis kode sumber generator RSA pada `chall.py` untuk mengidentifikasi ketiadaan padding OAEP/PSS.
  2. Mengidentifikasi eksponen publik berukuran kecil ($e = \text{0x11} = 17$) dan relasi linier $m_2 = m_1 + 3$.
  3. Mengonstruksi dua polinomial univariat $g_1(x)$ dan $g_2(x)$ di atas gelanggang polinomial $\mathbb{Z}_N[x]$ yang berbagi faktor akar $(x - m_1)$.
  4. Menerapkan algoritma pembagian Euclidean polinomial modulo $N$ (*Franklin-Reiter Related Message Attack*) untuk mengekstraksi $m_1$ tanpa faktorisasi prima terhadap $N$.
  5. Memvalidasi token plaintext resmi pada endpoint REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kerapuhan RSA Buku Teks (Textbook Unpadded RSA, RFC 8017 / CWE-327):**
   Algoritma RSA buku teks mengenkripsi pesan plaintext $M$ secara deterministik:
   $$C = M^e \pmod N$$
   Jika pengirim mengenkripsi dua pesan yang sangat mirip atau memiliki hubungan aljabar yang diketahui (misalnya koreksi salah ketik / *typo correction*), sifat homomorfik multiplikatif dan struktur aljabar modulus membuka celah serangan aljabar langsung. Standar RFC 8017 secara eksplisit mewajibkan penggunaan skema *Optimal Asymmetric Encryption Padding* (OAEP) untuk mengacak plaintext sebelum modular exponentiation dilakukan.

2. **Teorema Serangan Pesan Terkait Franklin-Reiter (Franklin-Reiter Related Message Attack):**
   Misalkan $(N, e)$ adalah kunci publik RSA di mana $e$ berukuran relatif kecil. Andaikan dua pesan $m_1, m_2 \in \mathbb{Z}_N$ dengan $m_1 \neq m_2 \pmod N$ memenuhi hubungan polinomial afinitas linier publik:
   $$m_2 \equiv f(m_1) \pmod N \quad \text{dengan} \quad f(x) = x + \Delta$$
   Dua ciphertext yang dihasilkan adalah:
   $$c_1 \equiv m_1^e \pmod N \quad \text{dan} \quad c_2 \equiv m_2^e \equiv (m_1 + \Delta)^e \pmod N$$
   Bentuk dua polinomial univariat pada gelanggang $\mathbb{Z}_N[x]$:
   $$g_1(x) = x^e - c_1 \pmod N$$
   $$g_2(x) = (x + \Delta)^e - c_2 \pmod N$$
   Perhatikan bahwa ketika $x = m_1$:
   $$g_1(m_1) = m_1^e - c_1 \equiv 0 \pmod N$$
   $$g_2(m_1) = (m_1 + \Delta)^e - c_2 = m_2^e - c_2 \equiv 0 \pmod N$$
   Artinya, polinomial linier $(x - m_1)$ merupakan faktor persekutuan dari $g_1(x)$ dan $g_2(x)$. Karena $e = 17$ sangat kecil, faktor persekutuan terbesar kedua polinomial:
   $$\gcd(g_1, g_2) \pmod N = (x - m_1)$$
   dapat dihitung secara efisien menggunakan algoritma Euclidean polinomial modulo $N$ dalam kompleksitas waktu $\mathcal{O}(e^2)$ operasi aritmetika besar, memecahkan plaintext dalam hitungan detik tanpa mengetahui faktorisasi $p$ dan $q$.

3. **Invertibilitas Koefisien Utama pada Gelanggang $\mathbb{Z}_N$:**
   Selama algoritma pembagian polinomial Euclidean berlangsung, koefisien utama (*leading coefficient*) pembagi wajib diinverskan modulo $N$:
   $$c^{-1} \equiv \text{pow}(c, -1, N) \pmod N$$
   Jika suatu koefisien utama $c$ tidak memiliki invers perkalian modular, maka $\gcd(c, N) > 1$, yang berarti kita secara kebetulan menemukan faktor non-trivial dari $N$ (memfaktorkan RSA secara langsung). Jika invertibel, reduksi derajat polinomial terus berlanjut hingga diperoleh derajat 1: $a_0 x + a_1 \equiv 0 \pmod N$.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Berkas `chall.py` & Ekstraksi Parameter `output.txt`:**
   Membaca parameter dari berkas keluaran:
   - Eksponen publik: $e = \text{0x11} = 17$.
   - Relasi pesan: $\text{Message} - \text{Message\_fixed} = -3$, sehingga $\Delta = 3$.
   - Ciphertext 1: $c_1$ (integer 616 digit).
   - Ciphertext 2: $c_2$ (integer 617 digit).
   - Modulus: $N$ (integer 617 digit / 2048 bit).

2. **Formulasi Polinomial pada $\mathbb{Z}_N[x]$:**
   Mendefinisikan fungsi representasi larik koefisien:
   $$g_1(x) = x^{17} - c_1$$
   $$g_2(x) = (x + 3)^{17} - c_2$$
   Ekspansi binomial terhadap $(x + 3)^{17}$:
   $$(x + 3)^{17} = \sum_{k=0}^{17} \binom{17}{k} 3^{17-k} x^k$$
   dikurangi $c_2 \pmod N$.

3. **Eksekusi Algoritma Euclidean Polinomial Modulo $N$:**
   Melakukan operasi pembagian bersisa polinomial (*polynomial modulo division*):
   ```python
   def poly_mod(a, b, N):
       a = list(a)
       while len(a) >= len(b) and any(a):
           c = (a[0] * pow(b[0], -1, N)) % N
           k = len(a) - len(b)
           sub = [(c * x) % N for x in b] + [0] * k
           a = [(x - y) % N for x, y in zip(a, sub)]
           while a and a[0] == 0:
               a.pop(0)
       return a or [0]

   a, b = g1, g2
   while any(b):
       a, b = b, poly_mod(a, b, N)
   ```
   Setelah 17 iterasi pembagian berulang, sisa pembagian terakhir menghasilkan polinomial derajat 1:
   $$a(x) = a_0 x + a_1 \pmod N$$

4. **Ekstraksi Akar Plaintext Monik:**
   Menghitung akar monik $m_1$:
   $$m_1 = -a_1 \cdot a_0^{-1} \pmod N$$
   Menghitung plaintext kedua yang telah diperbaiki:
   $$m_2 = m_1 + 3$$
   Mengonversi integer ke bita representasi ASCII:
   ```python
   recovered = m2.to_bytes((m2.bit_length() + 7) // 8, 'big')
   # Output: b"academy{m3ssage_w1th_typ0}"
   ```

5. **Validasi Submisi ke REST API CyLab Academy:**
   Mengirimkan token verifikasi ke endpoint `POST /api/submissions/` dengan payload JSON `{"challenge": 713, "flag": "academy{m3ssage_w1th_typ0}"}`:
   ```bash
   python3 scripts/solve_713_related_messages.py --submit
   ```
   Server mengembalikan kode status HTTP `201 Created` dengan konfirmasi validasi `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{m3ssage_w1th_typ0}`
- **Flag Komunitas:** `CTF{m3ssage_w1th_typ0}`
- **Log Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 713,
    "flag": "academy{m3ssage_w1th_typ0}",
    "correct": true,
    "historical": false
  }
  ```
  Status respons HTTP: `201 Created` mengonfirmasi token valid dan tercatat secara definitif pada basis data penilaian.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Rekomendasi Remediasi & Hardening (Defensive Perspective):**
   - **Wajibkan Skema Padding Asimetris Probabilistik (RSA-OAEP, RFC 8017):** Dilarang keras menggunakan RSA buku teks (*raw deterministic RSA*). Penggunaan Optimal Asymmetric Encryption Padding (OAEP) dengan fungsi hash SHA-256 menyuntikkan string acak (*random seed*) ke dalam setiap blok pesan sebelum enkripsi. Hal ini memastikan bahwa dua pesan yang identik atau memiliki relasi afinitas $\Delta$ akan menghasilkan representasi biner acak yang sama sekali tidak berhubungan (*semantic security under IND-CCA2*).
   - **Gunakan Eksponen Publik Standar ($e = 65537$):** Menghindari penggunaan nilai eksponen publik yang terlalu kecil ($e = 3, 5, 17$). Standar industri FIPS 186-5 dan NIST merekomendasikan $e = 2^{16} + 1 = 65537$, yang cukup besar untuk mempersulit serangan berbasis aljabar polinomial Coppersmith dan Franklin-Reiter.
   - **Pembaruan Pasangan Kunci & Pembatasan Re-use:** Jangan pernah mengenkripsi pesan revisi atau pesan diagnostik terkait menggunakan parameter kunci privat/publik yang sama secara deterministik.

2. **Relevansi Modul LKS Cyber Security:**
   - **Cryptanalysis & Algebra over Finite Rings:** Peserta kompetisi LKS Cyber Security diwajibkan memahami matematika kriptografi tingkat lanjut di luar modular aritmetika dasar, termasuk manipulasi polinomial pada gelanggang hingga $\mathbb{Z}_N[x]$ dan implementasi algoritma GCD Euclid.
   - **Audit Kerentanan Kriptografi Asimetris:** Kemampuan menganalisis kode implementasi kriptografi dan mengenali pola kegagalan padding yang memicu kebocoran data kritis.
