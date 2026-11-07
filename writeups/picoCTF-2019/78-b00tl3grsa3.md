# Writeup: b00tl3gRSA3 (Challenge ID: 78)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Multi-Prime RSA Decomposition & Generalized Euler Totient
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 250
- **Author:** John Hammond / picoCTF Team
- **Flag:** `academy{too_many_fact0rs_8024768}`

---

## Problem Statement & Scope
Tantangan `b00tl3gRSA3` menyajikan skema varian kunci publik RSA di mana modulus enkripsi $N$ tidak dibentuk dari dua bilangan prima besar standar ($p$ dan $q$), melainkan dibentuk dari akumulasi perkalian puluhan bilangan prima berukuran kecil:
```text
Why use p and q when I can use more?
```
Layanan memberikan:
1. Ciphertext terenkripsi $C$ (1138-bit integer).
2. Modulus publik $N$ (1138-bit integer).
3. Eksponen publik standar $e = 65537$.

Tujuan audit ini adalah membuktikan kerentanan dekomposisi faktorisasi pada varian Multi-Prime RSA berdasarkan standar NIST SP 800-115 Section 4.3, menerapkan generalisasi fungsi totient Euler, dan memulihkan kunci privat $d$ untuk mendekripsi teks flag rahasia.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kegagalan Asumsi Keamanan Multi-Prime RSA (CWE-326: Inadequate Encryption Strength):**
   Keamanan fundamental dari algoritma RSA (RFC 8017 / NIST SP 800-56B) bergantung langsung pada sulitnya masalah faktorisasi integer (*Integer Factorization Problem - IFP*). Dalam RSA 1024-bit standar, dua bilangan prima $p$ dan $q$ masing-masing berukuran $\approx 512$ bit, yang berada jauh melampaui kemampuan faktorisasi praktis algoritma konvensional.
   
   Pada implementasi `b00tl3gRSA3`, modulus $N$ berukuran 1138 bit dipecah menjadi perkalian $k = 34$ bilangan prima independen:
   $$N = \prod_{i=1}^{34} p_i$$
   Hal ini berakibat bahwa setiap bilangan prima komponen $p_i$ hanya memiliki ukuran rata-rata $\approx 34$ bit ($p_i \approx 10^{10}$).

2. **Dekomposisi Faktorisasi Cepat (Pollard's Rho & ECM):**
   Algoritma faktorisasi seperti Pollard's rho dan *Lenstra's Elliptic Curve Factorization* (ECM) memiliki kompleksitas waktu yang bergantung pada ukuran faktor prima terkecil ($O(p^{1/2})$), bukan ukuran keseluruhan modulus $N$. Bilangan prima dengan panjang 34-35 bit dapat difaktorkan dalam hitungan milidetik menggunakan pustaka faktorisasi atau basis data faktor global (FactorDB).

3. **Generalisasi Fungsi Totient Euler untuk Multi-Prime Square-Free:**
   Jika suatu bilangan komposit $N$ bebas kuadrat (*square-free*), yakni merupakan hasil kali faktor-faktor prima yang saling berbeda, maka fungsi totient Euler $\phi(N)$ bersifat multiplikatif penuh:
   $$\phi(N) = \prod_{i=1}^{k} (p_i - 1)$$
   Setelah $\phi(N)$ berhasil dihitung dari seluruh faktor prima $p_i$, eksponen privat $d$ dapat langsung diperoleh melalui invers modular terhadap eksponen publik $e$:
   $$d \equiv e^{-1} \pmod{\phi(N)}$$
   Pesan asli $M$ kemudian didekripsi secara langsung:
   $$M \equiv C^d \pmod N$$

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Struktur Parameter Modulus:**
   Parameter modulus $N$ diuji terhadap basis data faktorisasi terdistribusi (FactorDB / Pollard rho). Modulus berhasil terurai sepenuhnya menjadi 34 faktor prima diskret:
   - $p_1 = 10438103437$
   - $p_2 = 8876550257$
   - ...
   - $p_{34} = 14833004983$
   Hasil perkalian seluruh 34 faktor prima ini diverifikasi identik secara presisi dengan modulus $N$:
   $$\prod_{i=1}^{34} p_i == N$$

2. **Kalkulasi Totient Multi-Prime $\phi(N)$:**
   Totient dihitung dengan mengalikan $(p_i - 1)$ untuk seluruh 34 faktor prima:
   ```python
   phi = 1
   for p in factors:
       phi *= (p - 1)
   ```
   Diperoleh nilai $\phi(N)$ sepanjang 1138 bit.

3. **Inversi Kunci Privat:**
   Hitung eksponen privat $d$ menggunakan algoritma Euclidean yang diperluas (*Extended Euclidean Algorithm*):
   $$d = \text{pow}(e, -1, \phi)$$

4. **Dekripsi Ciphertext & Ekstraksi Flag:**
   Terapkan eksponensiasi modular untuk mendekripsi $C$:
   $$M = \text{pow}(C, d, N)$$
   Konversi integer $M$ ke dalam deretan byte ASCII menghasilkan teks terang:
   `picoCTF{too_many_fact0rs_8024768}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{too_many_fact0rs_8024768}`
- **Native Platform Flag:** `picoCTF{too_many_fact0rs_8024768}`
- **Status Solver:** Teruji dan terverifikasi penuh melalui modul solver reproduktif deterministik `scripts/solve_78_b00tl3g_rsa3.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Larangan Penggunaan Banyak Faktor Prima Kecil pada Modulus RSA:**
   Sesuai rekomendasi standar NIST SP 800-56B Rev. 2 (*Section 6.1: Key Pair Generation*), skema RSA strictly mensyaratkan modulus dibentuk tepat dari dua faktor prima besar ($N = p \cdot q$) dengan panjang bit yang seimbang ($|p| \approx |q| \ge 1024$ bit). Penggunaan lebih dari 2 faktor prima (*Multi-Prime RSA* RFC 3447) hanya diizinkan untuk keperluan akselerasi CRT dengan batas maksimal 3 faktor prima dan masing-masing faktor wajib memiliki panjang bit minimal $\ge 1024$ bit.

2. **Pengujian Kelayakan Komponen Kunci (Cryptographic Key Hygiene):**
   Dalam kerangka pengujian defensif LKS Cyber Security, tim security auditor wajib memverifikasi bahwa modul kriptografi yang diintegrasikan tidak menggunakan modul komposit yang dapat dipecah oleh algoritma Pollard's rho atau ECM. Seluruh pembangkitan bilangan prima wajib divalidasi melalui pengujian *Miller-Rabin Probabilistic Primality Test* dan *Lucas Probabilistic Primality Test* sesuai FIPS 186-4.
