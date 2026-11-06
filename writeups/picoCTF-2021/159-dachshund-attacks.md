# Writeup: Dachshund Attacks (Challenge ID: 159)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Asymmetric RSA
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2021
- **Points:** 250
- **Flag:** `academy{d4ch5hund_w13n3r_5m4ll_d_4tt4ck}`

---

## Problem Statement & Scope

Tantangan ini menanyakan kelemahan mendasar dalam parameterisasi kunci RSA:
> *"What if $d$ is too small?"*
> 
> Disediakan berkas petunjuk `dachshund.jpg` (anjing berjenis Dachshund / Wiener dog) yang mengarah secara alegoris ke **Wiener's Attack**.

Diberikan modulus publik $n$, eksponen enkripsi $e$, dan ciphertext flag $c$. Eksponen dekripsi privat $d$ dipilih terlalu kecil untuk mempercepat proses dekripsi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Inadequate Encryption Strength - Small Private Exponent (CWE-326):**
   Michael J. Wiener (1990) membuktikan bahwa jika eksponen dekripsi privat $d$ memenuhi batas:
   $$d < \frac{1}{3} n^{1/4}$$
   maka $d$ dapat dipulihkan dalam waktu polinomial menggunakan algoritma ekspansi pecahan berlanjut (*continued fractions expansion*) terhadap fraksi $\frac{e}{n}$.
2. **Koneksi Matematika Pecahan Berlanjut:**
   Dari relasi kunci RSA $ed - k\phi(n) = 1$, dapat dibentuk aproksimasi:
   $$\left| \frac{e}{n} - \frac{k}{d} \right| < \frac{1}{2d^2}$$
   Berdasarkan teorema Legendre dalam aproksimasi Diophantine, fraksi $\frac{k}{d}$ pasti merupakan salah satu *konvergen* (*convergents*) dari ekspansi pecahan berlanjut $\frac{e}{n}$.
3. **Faktorisasi Modulus $n$:**
   Untuk setiap konvergen $\frac{k}{d}$, kita dapat menghitung kandidat $\phi(n) = \frac{ed - 1}{k}$. Nilai $p$ dan $q$ kemudian dapat diselesaikan melalui persamaan kuadrat:
   $$x^2 - (n - \phi(n) + 1)x + n = 0$$
   Jika diskriminan $\Delta$ menghasilkan kuadrat sempurna dan akar-akarnya bernilai integer positif yang membagi $n$, maka $d$ adalah eksponen privat yang valid.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Mengambil parameter publik $e, n$ dan ciphertext $c$ dari instans tantangan.
2. Menjalankan algoritma ekspansi pecahan berlanjut terhadap fraksi $\frac{e}{n}$ untuk menghasilkan urutan hasil bagi $q_0, q_1, q_2, \dots$.
3. Menghitung urutan konvergen pecahan $\frac{h_i}{k_i}$.
4. Menguji setiap pasangan $(k, d) = (h_i, k_i)$ apakah $(ed - 1)$ habis dibagi $k$.
5. Jika habis dibagi, verifikasi apakah akar-akar persamaan kuadrat $x^2 - (n - \phi(n) + 1)x + n = 0$ adalah faktor prima dari $n$.
6. Gunakan nilai $d$ yang ditemukan untuk mendekripsi ciphertext:
   $$m \equiv c^d \pmod n$$
7. Konversi nilai integer $m$ ke format ASCII/UTF-8 untuk memperoleh string flag.

---

## Flag & Verifikasi

- **Flag:** `academy{d4ch5hund_w13n3r_5m4ll_d_4tt4ck}`
- **Validasi Platform:** Solved on CyLab Academy.

---

## Remediasi & Mitigasi (Perspektif Defensive LKS)

1. **Gunakan Eksponen Publik Standar:**
   Selalu gunakan nilai eksponen publik standar $e = 65537$ ($2^{16} + 1$). Pemilihan nilai $e$ ini menjamin bahwa eksponen privat $d$ akan berukuran penuh mendekati $n$ ($\approx 2048$ bit).
2. **Hindari Optimasi Berisiko pada Kunci Privat:**
   Jangan pernah memilih $d$ kecil untuk tujuan mempercepat operasi dekripsi atau pembuatan signature. Jika kecepatan dekripsi diperlukan, gunakan optimasi *Chinese Remainder Theorem* (RSA-CRT) yang menggunakan $d_p = d \pmod{p-1}$ dan $d_q = d \pmod{q-1}$ tanpa mengorbankan panjang $d$ penuh.
