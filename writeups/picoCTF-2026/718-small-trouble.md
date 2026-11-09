# Writeup: Small Trouble (Challenge ID: 718)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / RSA Small Private Exponent Attack (Wiener's Continued Fractions)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** picoCTF
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{sm4ll_d_46c3352b}`
- **Flag Komunitas:** `CTF{sm4ll_d_46c3352b}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 8017 (PKCS #1 v2.2: RSA Cryptography Standard), FIPS 186-4 / FIPS 186-5 (Digital Signature Standard Parameter Requirements), CWE-326 (Inadequate Encryption Strength), & Wiener's Attack on Short Secret Exponents.

---

## Problem Statement & Scope

Pada modul bimbingan teknis persiapan lomba LKS `Small Trouble`, peserta diuji dalam menganalisis batas keamanan parameter matematis kriptografi kunci publik RSA:
- Skenario lingkungan: Diberikan dua berkas artefak:
  1. Skrip pembuat kunci dan enkripsi Python: `encryption.py`.
  2. Berkas keluaran parameter kriptografis: `message.txt` yang memuat modulus $n$ (~2096 bit), eksponen publik $e$ (~2096 bit), dan ciphertext $c$.
- Pernyataan tantangan:
  > *"Everything seems secure; strong numbers, familiar parameters but something small might ruin it all. Can you recover the message?"*
- Petunjuk resmi investigasi:
  1. *"This might be a job for Boneh-Durfee."*
- Sasaran pengujian: Menganalisis ketidakseimbangan ukuran bit eksponen privat $d$ terhadap modulus $n$, merekonstruksi aproksimasi pecahan berlanjut (*continued fractions*) rasio $e/n$, memulihkan pasangan $k/d$ konvergen menurut Teorema Wiener, memfaktorkan modulus $n$ menjadi faktor prima $p$ dan $q$, mendekripsi pesan rahasia, serta memvalidasi token resmi pada endpoint REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Relasi Matematika RSA & Definisi Eksponen Privat:**
   Dalam sistem kriptografi RSA, dua bilangan prima acak $p$ dan $q$ menghasilkan modulus $n = p \cdot q$ dan fungsi totient Euler $\phi(n) = (p - 1)(q - 1)$.
   Kunci publik $e$ dan kunci privat $d$ memenuhi relasi kongruensi linear:
   $$e \cdot d \equiv 1 \pmod{\phi(n)}$$
   yang dapat dituliskan dalam bentuk persamaan bilangan bulat:
   $$e \cdot d - k \cdot \phi(n) = 1 \quad \text{untuk suatu bilangan bulat } k \ge 1$$

2. **Kelemahan Eksponen Privat Kecil (Wiener's Theorem, CWE-326):**
   Untuk mempercepat proses dekripsi dan penandatanganan digital, beberapa implementasi ceroboh memilih nilai eksponen privat $d$ yang relatif kecil.
   Namun, matematikawan Michael J. Wiener membuktikan bahwa jika nilai $d$ memenuhi batasan:
   $$d < \frac{1}{3} n^{1/4}$$
   maka rasio bilangan bulat $k/d$ merupakan salah satu konvergen (*convergent*) dari ekspansi pecahan berlanjut (*continued fraction expansion*) dari nilai rasio publik $e/n$.
   Pada tantangan ini:
   - Modulus $n$ dibangun dari dua prima 1048-bit sehingga $\text{bitlen}(n) \approx 2096$ bit.
   - Ambang batas Wiener: $n^{1/4} \approx 2^{524}$ bit, sehingga $\frac{1}{3} n^{1/4} \approx 2^{522}$ bit.
   - Skrip `encryption.py` menetapkan: `d = getPrime(256)`, yakni $d \approx 2^{256}$.
   - Karena $2^{256} \ll 2^{522}$, kondisi batas Wiener terpenuhi secara mutlak dengan margin keamanan yang sangat lebar, memungkinkan rekonstruksi $d$ dalam hitungan milidetik tanpa memerlukan *lattice reduction* Coppersmith / Boneh-Durfee.

3. **Verifikasi Deterministik & Faktorisasi Modulus $n$:**
   Untuk setiap konvergen $k/d$ dari $e/n$:
   - Hitung calon fungsi totient: $\phi' = \frac{e \cdot d - 1}{k}$.
   - Jika $(e \cdot d - 1) \pmod k \neq 0$, abaikan kandidat tersebut.
   - Konstruksikan persamaan kuadrat yang akar-akarnya adalah prima $p$ dan $q$:
     $$x^2 - ((n - \phi') + 1)x + n = 0$$
   - Hitung diskriminan $\Delta = ((n - \phi') + 1)^2 - 4n$.
   - Jika $\Delta \ge 0$ dan $\lfloor\sqrt{\Delta}\rfloor^2 == \Delta$, maka akar kuadrat sempurna ditemukan, menghasilkan nilai pasti $p = \frac{(n - \phi' + 1) + \sqrt{\Delta}}{2}$ dan $q = \frac{(n - \phi' + 1) - \sqrt{\Delta}}{2}$.
   - Verifikasi $p \cdot q == n$ mengonfirmasi pemulihan kunci privat yang valid.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pemeriksaan Berkas Sumber `encryption.py`:**
   Membaca alur pembuatan parameter kunci:
   ```python
   p = getPrime(1048)
   q = getPrime(1048)
   n = p * q
   phi = (p - 1) * (q - 1)
   d = getPrime(256)
   e = inverse(d, phi)
   ```
   Dikonfirmasi bahwa $d$ dihasilkan dengan ukuran tetap 256-bit sementara $n$ berukuran 2096-bit.

2. **Ekstraksi Parameter dari `message.txt`:**
   Mengekstrak nilai $n$, $e$, dan $c$:
   - $\text{bitlen}(n) = 2096$
   - $\text{bitlen}(e) = 2095$
   - $\text{bitlen}(c) = 2095$

3. **Komputasi Pecahan Berlanjut & Konvergen $e/n$:**
   Menghitung koefisien pecahan berlanjut $[q_0, q_1, q_2, \dots]$ dari $e/n$ menggunakan algoritma Euclidean:
   ```python
   cf = []
   a, b = e, n
   while b:
       q = a // b
       cf.append(q)
       a, b = b, a - q * b
   ```
   Membangkitkan deret konvergen $(k_i, d_i)$.

4. **Uji Kandidat & Pemulihan Eksponen $d$:**
   Mengiterasi konvergen hingga menemukan diskriminan kuadrat sempurna:
   - Pada iterasi konvergen ke-85, ditemukan pembagi bulat $(e \cdot d - 1) \pmod k == 0$.
   - Diskriminan $\Delta$ membentuk bilangan kuadrat sempurna.
   - Diperoleh eksponen privat asli: $d$ (256 bit).
   - Modulus $n$ berhasil difaktorkan menjadi $p$ (1048 bit) dan $q$ (1048 bit).

5. **Dekripsi Ciphertext & Pemulihan Flag:**
   Mengeksekusi modular exponentiation $m = c^d \pmod n$:
   ```python
   m = pow(c, d, n)
   flag = m.to_bytes((m.bit_length() + 7) // 8, "big").decode()
   ```
   Hasil: `academy{sm4ll_d_46c3352b}`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{sm4ll_d_46c3352b}`
- **Flag Komunitas:** `CTF{sm4ll_d_46c3352b}`
- **Log Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 718,
    "flag": "academy{sm4ll_d_46c3352b}",
    "correct": true,
    "historical": false
  }
  ```
  Status respons HTTP: `201 Created` mengonfirmasi token valid dan tercatat secara definitif.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Rekomendasi Remediasi & Hardening (Defensive Perspective):**
   - **Pemilihan Ukuran Parameter Kunci Sesuai Standar FIPS 186-5:** Eksponen privat $d$ tidak boleh dipilih secara manual atau dibatasi ukurannya. Eksponen publik standar yang direkomendasikan adalah nilai tetap $e = 65537$ ($2^{16} + 1$), dan nilai $d$ harus dihitung sebagai invers modular $d = e^{-1} \pmod{\phi(n)}$, yang secara statistik menghasilkan ukuran bit $d \approx \text{bitlen}(n)$.
   - **Validasi Ambang Batas Wiener pada Siklus Generasi Kunci:** Perangkat lunak pembangkit kunci kriptografi wajib memverifikasi bahwa $d > \frac{1}{3} n^{1/4}$ dan $d > 2^{n/2}$ untuk mencegah serangan pecahan berlanjut serta serangan kisi (*lattice attacks*).
   - **Pemanfaatan Chinese Remainder Theorem (CRT):** Jika optimasi kecepatan dekripsi diperlukan, gunakan representasi CRT ($(dp, dq, q_{inv})$) dengan prima rahasia yang aman, bukan dengan memperkecil ukuran eksponen global $d$.

2. **Relevansi Modul LKS Cyber Security:**
   - **Analisis Kerentanan Kriptografi Asimetris:** Peserta LKS Cyber Security dituntut memahami bahwa bilangan besar saja tidak menjamin keamanan sistem; ketidakseimbangan parameter matematis internal dapat meruntuhkan kerahasiaan algoritma.
   - **Implementasi Algoritma Teori Bilangan Mandiri:** Memperkuat kompetensi peserta dalam merealisasikan algoritma Euclidean diperluas, pecahan berlanjut, dan uji akar kuadrat bilangan bulat raksasa (*arbitrary-precision integer arithmetic*) dalam bahasa Python.
