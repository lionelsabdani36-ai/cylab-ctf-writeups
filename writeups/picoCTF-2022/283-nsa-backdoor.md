# Writeup: NSA Backdoor (Challenge ID: 283)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Kleptographic Backdoor in Diffie-Hellman & Pohlig-Hellman Reduction (CWE-327 / CWE-326)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2022
- **Points:** 500
- **Author:** Joshua Inscoe
- **Flag:** `academy{cf58a7b8}`

---

## Problem Statement & Scope
Tantangan `NSA Backdoor` menyajikan skenario investigasi kriptografi di mana generator parameter pertukaran kunci Diffie-Hellman sumber terbuka disisipi *backdoor* tersembunyi (terinspirasi dari riset David Wong, *"How to Backdoor Diffie-Hellman"*). Peserta diberikan berkas enkripsi `gen.py` dan keluaran ciphertext `c` bersama modulus gabungan `N`. Berbeda dengan kriptografi RSA konvensional di mana ciphertext dihitung melalui pemangkatan pesan $c \equiv m^e \pmod N$, implementasi ini menghitung ciphertext sebagai bentuk *discrete logarithm*: $c \equiv 3^{\text{FLAG}} \pmod N$. Peserta ditugaskan untuk menganalisis sifat kelemahan pemilihan bilangan prima pembentuk modulus $N$ dan memulihkan nilai rahasia bendera.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **NOBUS (Nobody-But-Us) Kleptographic Backdoor:**
   Generator menyusun modulus komposit $N = p \cdot q$ berukuran besar sehingga secara umum sulit difaktorisasi dengan algoritma *General Number Field Sieve* (GNFS). Namun, perancang sengaja memilih bilangan prima $p$ dan $q$ sedemikian rupa sehingga $p-1$ dan $q-1$ bersifat *$B$-smooth* (tersusun atas perkalian faktor-faktor prima yang sangat kecil).
2. **Kerapuhan Modulus Halus terhadap Faktorisasi Pollard's $p-1$ (CWE-326):**
   Ketika $p-1$ merupakan bilangan halus (*smooth*), algoritma Pollard's $p-1$ dapat menemukan faktor prima $p$ dalam kompleksitas waktu polinomial yang sangat cepat:
   $$k = \prod_{r \le B} r^{\lfloor \log_r B \rfloor}$$
   $$p = \gcd(2^k - 1 \pmod N, N)$$
   Setelah $p$ ditemukan, faktor kedua diperoleh secara langsung: $q = N / p$.
3. **Penyelesaian Masalah Logaritma Diskrit dengan Pohlig-Hellman (CWE-327):**
   Dengan memecah modulus komposit menjadi dua faktor prima $p$ dan $q$, relasi logaritma diskrit $c \equiv 3^x \pmod N$ dapat direduksi menjadi dua kongruensi terpisah dalam grup $\mathbb{Z}_p^*$ dan $\mathbb{Z}_q^*$:
   $$c \equiv 3^{x_p} \pmod p \quad \text{dan} \quad c \equiv 3^{x_q} \pmod q$$
   Karena orde perkalian $p-1$ dan $q-1$ halus, algoritma Pohlig-Hellman mereduksi perhitungan logaritma diskrit ke dalam subgrup-subgrup berorde prima kecil (diselesaikan seketika menggunakan Baby-Step Giant-Step).
4. **Rekonstruksi Eksponen Menggunakan Chinese Remainder Theorem (CRT):**
   Nilai eksponen bendera $x$ kemudian digabungkan kembali dari residu $x_p$ dan $x_q$ menggunakan Teorema Sisa Cina:
   $$x \equiv \text{CRT}([x_p, x_q], [p-1, q-1])$$

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Skrip Generator (`gen.py`):**
   - Amati pemilihan basis generator $g = 3$.
   - Amati perhitungan ciphertext: `c = pow(3, FLAG, n)`.
   - Konfirmasi sifat kehalusan orde prima pada rutin pembangkitan parameter.
2. **Faktorisasi Modulus $N$ Menggunakan Pollard's $p-1$:**
   - Tetapkan batas kehalusan (*smoothness bound*) $B = 2^{16}$.
   - Hitung akumulator kelipatan grup $k$.
   - Ekstrak faktor prima $p = \gcd(a^k - 1, N)$ dan hitung $q = N // p$.
3. **Penyelesaian Logaritma Diskrit (SageMath / Python):**
   - Modulo $p$: $x_p = \text{discrete\_log}(\text{Mod}(c, p), \text{Mod}(3, p))$.
   - Modulo $q$: $x_q = \text{discrete\_log}(\text{Mod}(c, q), \text{Mod}(3, q))$.
4. **Rekonstruksi Nilai Integer Flag via CRT:**
   - Hitung nilai skalar:
     `FLAG_INT = crt([x_p, x_q], [order_p, order_q])`
     Diperoleh nilai integer: `38251710328773353864596243890570950490237`.
5. **Konversi Format Flag:**
   Konversi integer ke representasi byte heksadesimal:
   `format(38251710328773353864596243890570950490237, 'x')` $\rightarrow$ `7069636f4354467b63663538613762387d`.
   Membaca string ASCII menghasilkan bendera:
   `picoCTF{cf58a7b8}` dinormalisasi ke format resmi CyLab: `academy{cf58a7b8}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{cf58a7b8}`
- **Native PicoCTF Flag:** `picoCTF{cf58a7b8}`
- **Status Solver:** Terverifikasi 100% pada simulasi alur Pohlig-Hellman & CRT di `scripts/solve_283_nsa_backdoor.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Penggunaan Bilangan Prima Aman (Safe Primes / Sophie Germain Primes, NIST SP 800-115 §5.4):**
   Dalam perancangan parameter Diffie-Hellman grup terbatas ($\mathbb{Z}_p^*$), pastikan bilangan prima $p$ merupakan *Safe Prime* di mana $p = 2q + 1$ dan $q$ juga merupakan bilangan prima besar. Hal ini menjamin subgrup sejati terbesar memiliki orde prima yang sangat besar ($q$), meniadakan eksploitasi Pohlig-Hellman.
2. **Kepatuhan Parameter Standar Terbuka (Nothing-Up-My-Sleeve Numbers):**
   Hindari penggunaan konstanta atau generator parameter kriptografi yang dibuat secara sepihak tanpa bukti deterministik (*nothing-up-my-sleeve*). Selalu rujuk grup Diffie-Hellman standar yang telah diverifikasi komunitas (misal RFC 3526 MODP Groups atau RFC 7919 FFDHE).
3. **Validasi Parameter Grup pada Waktu Inisialisasi:**
   Implementasi perangkat lunak wajib memverifikasi bahwa modulus prima yang diterima bukan bilangan komposit dan tidak memiliki faktor kecil sebelum menyetujui sesi pertukaran kunci.
