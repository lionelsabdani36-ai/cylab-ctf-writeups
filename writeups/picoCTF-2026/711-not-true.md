# Writeup: Not TRUe (Challenge ID: 711)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Lattice-Based Cryptography (NTRU Coppersmith-Shamir Attack)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** ishaanharrry
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{th4ts_s0_N0t_TRU3_d78e9bcb}`
- **Flag Komunitas:** `CTF{th4ts_s0_N0t_TRU3_d78e9bcb}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard), RFC 8391 (XMSS / Post-Quantum Cryptography), CWE-327 (Use of Broken Cryptographic Algorithm), CWE-326 (Inadequate Encryption Strength), & FIPS 140-3 Cryptographic Algorithmic Strength.

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis LKS Cyber Security `Not TRUe`, peserta diuji dalam menganalisis skema kriptografi pasca-kuantum (*Post-Quantum Cryptography* / PQC) berbasis kisi (*lattice-based cryptography*), khususnya implementasi purwarupa sistem enkripsi kunci publik NTRU (*N-th degree Truncated polynomial Ring Units*):
- Skenario lingkungan: Diberikan dua berkas artefak statis:
  1. `encrypt.py`: Skrip implementasi algoritma NTRU dengan parameter mainan (*toy parameters*).
  2. `public.txt`: Berkas keluaran publik yang memuat polinomial kunci publik $h(x)$ serta 6 blok *ciphertext* terenkripsi $c_0, c_1, \dots, c_5$.
- Pernyataan tantangan:
  > *"no. no. that's Not TRUe. that's impossible! Download encryption script and public info."*
- Sasaran pengujian:
  1. Menganalisis struktur gelanggang polinomial terpotong $R = \mathbb{Z}[x] / (x^N - 1)$ dengan parameter $N = 48$, modulus kecil $p = 3$, dan modulus besar $q = 509$.
  2. Mengidentifikasi kelemahan dimensi kisi $N = 48$ terhadap serangan reduksi basis kisi Coppersmith-Shamir.
  3. Membangun representasi matriks kisi berdimensi $2N \times 2N$ ($96 \times 96$) yang memuat vektor kunci privat pendek $(f, p \cdot g)$.
  4. Menerapkan algoritma Lenstra-Lenstra-Lovasz (LLL) menggunakan *fpylll* untuk memulihkan polinomial privat $f(x)$.
  5. Menyelesaikan ambiguitas rotasi siklik dan tanda pada gelanggang polinomial, menginversi $f(x) \pmod{p, x^N - 1}$ via algoritma Euclidean yang diperluas, dan mendekripsi pesan teks bendera.
  6. Mengirimkan token verifikasi ke endpoint REST API CyLab Academy (`POST /api/submissions/`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Kriptosistem NTRU:**
   NTRU beroperasi pada gelanggang polinomial terpotong $R = \mathbb{Z}[x] / (x^N - 1)$. Elemen-elemen gelanggang adalah polinomial berderajat kurang dari $N$ dengan operasi penjumlahan dan perkalian polinomial modulo $x^N - 1$ (konvolusi siklik):
   $$(a \cdot b)_k = \sum_{i+j \equiv k \pmod N} a_i b_j$$
   Prosedur pembentukan kunci:
   - Dipilih dua polinomial privat pendek $f(x), g(x) \in R$ dengan koefisien terner berbobot rendah $\{-1, 0, 1\}$.
   - Dihitung invers $f_q(x) \equiv f^{-1}(x) \pmod q$ dan $f_p(x) \equiv f^{-1}(x) \pmod p$.
   - Polinomial kunci publik dipublikasikan sebagai:
     $$h(x) \equiv p \cdot f_q(x) \cdot g(x) \pmod q$$
   Prosedur enkripsi:
   - Pesan biner/terner $m(x)$ dan polinomial acak ephemeral $r(x)$ dienkripsi menjadi:
     $$c(x) \equiv p \cdot h(x) \cdot r(x) + m(x) \pmod q$$
   Prosedur dekripsi:
   - Penerima menghitung $a(x) \equiv f(x) \cdot c(x) \pmod q$. Substitusi $h(x)$ menghasilkan:
     $$a(x) \equiv f(x) \cdot (p \cdot p \cdot f_q(x) \cdot g(x) \cdot r(x) + m(x)) \equiv p^2 \cdot g(x) \cdot r(x) + f(x) \cdot m(x) \pmod q$$
   - Jika koefisien berada dalam rentang $(-q/2, q/2]$, pengurangan modulo $p$ mengeliminasi suku $p^2 \cdot g \cdot r$:
     $$a(x) \pmod p \equiv f(x) \cdot m(x) \pmod p$$
   - Mengalikan dengan $f_p(x)$ memulihkan pesan: $m(x) \equiv f_p(x) \cdot a(x) \pmod p$.

2. **Kelemahan Dimensi Mainan & Serangan Kisi Coppersmith-Shamir (CWE-327 / CWE-326):**
   Keamanan NTRU bertumpu pada sulitnya memecahkan masalah vektor terpendek (*Shortest Vector Problem* / SVP) atau vektor terdekat (*Closest Vector Problem* / CVP) pada kisi berdimensi tinggi.
   - Pada standar modern (seperti NIST FIPS 203 / ML-KEM atau NTRU NIST PQC), dimensi $N$ berada pada rentang $509 \le N \le 821$, sehingga reduksi kisi membutuhkan kompleksitas waktu eksponensial $2^{\mathcal{O}(N)}$.
   - Namun, pada tantangan ini, dimensi ditetapkan sebesar $N = 48$.
   - Dari hubungan kunci publik:
     $$f(x) \cdot h(x) \equiv p \cdot g(x) \pmod q$$
     Dapat dibentuk kisi bilangan bulat $L$ berdimensi $2N = 96$ dengan basis baris:
     $$B = \begin{pmatrix} I_N & C(h) \\ 0 & q I_N \end{pmatrix}$$
     Di mana $C(h)$ adalah matriks sirkulan $N \times N$ dari polinomial $h(x)$:
     $$C(h)_{i,j} = h_{(j - i) \pmod N}$$
   - Vektor $v = (f, p \cdot g)$ merupakan anggota kisi $L$, karena:
     $$(f, 0) \cdot B = (f, f \cdot C(h)) = (f, p \cdot g + k \cdot q) \equiv (f, p \cdot g) \pmod q$$
   - Panjang norma Euclidean vektor privat $v$:
     $$\|v\| = \sqrt{\sum_{i=0}^{N-1} f_i^2 + \sum_{i=0}^{N-1} (p \cdot g_i)^2} \le \sqrt{48 \cdot 1^2 + 48 \cdot 3^2} = \sqrt{480} \approx 21.91$$
   - Berdasarkan Teorema Minkowski, norma perkiraan vektor acak terpendek kisi $L$ adalah:
     $$\lambda_1(L) \approx \sqrt{2N} \cdot (\det L)^{1/(2N)} = \sqrt{96} \cdot (q^N)^{1/96} = \sqrt{96} \cdot \sqrt{509} \approx 9.798 \times 22.561 \approx 221.05$$
   - Karena $\|v\| \approx 21.91 \ll 221.05$, vektor kunci privat merupakan anomali sangat pendek (*extremely short vector gap* $\approx 10\times$). Algoritma reduksi basis LLL (Lenstra-Lenstra-Lovasz) memulihkan vektor tersebut dalam pecahan detik.

3. **Ambiguitas Simetri Rotasi Siklik dan Pembalikan Tanda:**
   Di dalam gelanggang $R = \mathbb{Z}[x] / (x^N - 1)$, perkalian dengan monomial $x^k$ hanya menggeser koefisien secara sirkular. Jika $f(x)$ adalah kunci privat yang valid, maka $\pm x^k \cdot f(x)$ untuk $0 \le k < N$ juga memenuhi relasi kisi yang sama.
   - Diperlukan pencarian mendatar (*linear sweep*) pada 2 tanda ($\pm 1$) dan 48 rotasi siklik.
   - Rotasi yang tepat akan menghasilkan invers $f_p(x)$ di gelanggang terner $\mathbb{F}_3[x] / (x^N - 1)$ dan mendekripsi blok biner menjadi karakter ASCII yang dapat dibaca (*printable flag*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Ekstraksi Parameter Publik dari Berkas Artefak:**
   Membaca parameter dari `public.txt`:
   - $N = 48, p = 3, q = 509$.
   - Koefisien kunci publik $h(x) = [336, 125, 418, \dots, 98]$ (48 koefisien).
   - Enam blok *ciphertext* $c_0, c_1, \dots, c_5$, masing-masing 48 integer modulo 509.

2. **Penyusunan Matriks Kisi 96 x 96 (Coppersmith-Shamir Construction):**
   Mengonstruksi matriks basis integer $B \in \mathbb{Z}^{96 \times 96}$:
   - Blok kiri-atas ($48 \times 48$): Matriks identitas $I_{48}$.
   - Blok kanan-atas ($48 \times 48$): Matriks konvolusi sirkulan $C(h)$ modulo 509.
   - Blok kiri-bawah ($48 \times 48$): Matriks nol $0_{48}$.
   - Blok kanan-bawah ($48 \times 48$): Matriks skalar $q \cdot I_{48} = 509 \cdot I_{48}$.

3. **Eksekusi Reduksi Basis Kisi LLL:**
   Menjalankan algoritma LLL pada basis $B$:
   ```python
   from fpylll import IntegerMatrix, LLL

   B = IntegerMatrix(96, 96)
   # Isi matriks sesuai konstruksi Coppersmith-Shamir
   LLL.reduction(B)
   ```
   LLL mengidentifikasi kandidat vektor terpendek dengan komponen kiri $f$ yang memiliki koefisien terner $\max(|f_i|) \le 2$ dan produk konvolusi modulo $q$ yang sangat kecil.

4. **Inversi Polinomial di GF(3)[x] / (x^48 - 1) & Dekripsi Blok:**
   - Untuk tiap kandidat vektor $f$, diuji 48 kemungkinan rotasi siklik dan tanda $\pm 1$.
   - Menghitung $f_p^{-1}(x)$ menggunakan algoritma pembagian polinomial Euclidean pada lapangan berhingga $\mathbb{F}_3$.
   - Mendekripsi 6 blok *ciphertext*:
     $$a_k(x) = (f(x) \cdot c_k(x) \pmod q) \in (-254, 254]$$
     $$m_k(x) = f_p^{-1}(x) \cdot (a_k(x) \pmod 3) \pmod 3$$
   - Mengubah bit biner menjadi bita ASCII (8 bit per karakter, MSB-first).
   - Blok teks berhasil didekripsi dan mengungkap token:
     `academy{th4ts_s0_N0t_TRU3_d78e9bcb}`

5. **Verifikasi Otomatis pada REST API Platform CyLab:**
   Token dikirimkan melalui HTTP POST ke endpoint resmi:
   ```bash
   python3 scripts/solve_711_not_true.py --submit
   ```
   Respons platform: HTTP 201 Created dengan status `{"correct": true}`.

---

## Flag & Bukti Verifikasi

- **Flag Resmi CyLab:** `academy{th4ts_s0_N0t_TRU3_d78e9bcb}`
- **Flag Format Komunitas:** `CTF{th4ts_s0_N0t_TRU3_d78e9bcb}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 711, "flag": "academy{th4ts_s0_N0t_TRU3_d78e9bcb}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Pemahaman Parameter Keamanan Kriptografi Berbasis Kisi:**
   Pada modul *Cryptography & Post-Quantum Security* lomba LKS Cyber Security, peserta wajib memahami bahwa keamanan algoritma kisi (seperti Kyber, Dilithium, NTRU) sangat bergantung pada dimensi polinomial $N$. Mengurangi dimensi demi efisiensi komputasi atau memori membuka celah fatal terhadap algoritma reduksi basis kisi (LLL dan BKZ).

2. **Rekomendasi Remediasi & Hardening (NIST FIPS 203 / FIPS 140-3):**
   - **Gunakan Standar NIST PQC Resmi:** Gunakan parameter yang telah distandarisasi secara ketat oleh NIST, seperti ML-KEM-512 ($k=2, d=256$), ML-KEM-768, atau NTRU-HPS-2048-509 ($N=509$), di mana serangan LLL/BKZ membutuhkan kerja komputasi melebihi $2^{128}$ operasi.
   - **Tolak Penggunaan Purwarupa Non-Standar:** Jangan pernah mengimplementasikan kriptosistem kisi dengan parameter kustom tanpa analisis ketahanan SVP mendalam.
   - **Validasi Invertibilitas & Noise Distribution:** Pastikan distribusi polinomial derau (*noise polynomials*) memenuhi standar keamanan IND-CCA2 menggunakan transformasi Fujisaki-Okamoto (FO Transform).
