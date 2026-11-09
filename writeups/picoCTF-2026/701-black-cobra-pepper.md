# Writeup: Black Cobra Pepper (Challenge ID: 701)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Linear Affine Cryptanalysis over GF(2) (AES without S-Box)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** CyLab Cryptography Team
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{spi1cy!}`
- **Flag Komunitas:** `CTF{spi1cy!}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), FIPS 197 (Advanced Encryption Standard - AES), ISO/IEC 18033-3 (Block Ciphers), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), & CWE-310 (Cryptographic Issues).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis LKS Cyber Security `Black Cobra Pepper`, peserta diuji dalam menganalisis kelemahan perancangan cipher blok modifikasi di mana komponen non-linear (*Substitution Box / S-Box*) dihilangkan:
- **Skenario Lingkungan:** Diberikan berkas skrip algoritma `chall.py` dan rekaman keluaran `output.txt`:
  1. Skrip `chall.py` mengimplementasikan struktur Substitution-Permutation Network (SPN) 128-bit mirip AES-128 dengan 10 putaran (*rounds*).
  2. Fungsi substitusi non-linear `sub_bytes()` dan `sub_word()` digantikan oleh fungsi identitas (`return s` / `return w`), serta konstanta putaran `rcon()` dinonaktifkan.
  3. Berkas `output.txt` menyajikan pasangan *Known-Plaintext*:
     - Ciphertext $ct_1$ dari plaintext uji $pt_1 = \text{"randomdata111111"}$ (heksadesimal: `72616e646f6d64617461313131313131`):
       ```text
       ct1 = d7481d89f1aaf5a857f56edd2ae8994c
       ```
     - Ciphertext $ct_2$ yang mengenkripsi flag rahasia dengan kunci utama (*master key*) yang sama:
       ```text
       ct2 = e5506260c6369f5d948419c2955fa236
       ```
- **Batasan & Arsitektur Lab:**
  1. Transformasi blok yang tersisa mencakup `AddRoundKey` (penjumlahan XOR pada GF(2)), `ShiftRows` (permutasi posisi byte), `MixColumns` (perkalian matriks linear atas GF($2^8$)), dan perluasan kunci `gen_keys()`.
  2. Seluruh operasi yang tersisa sepenuhnya linear terhadap penjumlahan biner GF(2) (operasi XOR).
- **Sasaran Pengujian:**
  1. Membuktikan reduksi matematis cipher AES tanpa S-box menjadi pemetaan afin (*affine transformation*) atas ruang vektor GF(2)$^{128}$.
  2. Memanfaatkan sifat titik tetap (*fixed point*) kunci nol ($k = 0$) untuk memisahkan komponen linear independen $L(p)$ dari pergeseran dependensi kunci $F(k)$.
  3. Mengekstraksi pergeseran kunci $F(k) = ct_1 \oplus L(pt_1)$ dari pasangan known-plaintext.
  4. Mendekripsi ciphertext $ct_2$ melalui inversi pemetaan linear dengan kunci nol ($D_0$) dan memvalidasi token resmi ke REST API CyLab Academy (`POST /api/submissions/`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Peran Fundamental S-Box pada Substitution-Permutation Network (FIPS 197):**
   Arsitektur cipher modern Shannon mengombinasikan dua prinsip utama: *Confusion* (kebingungan) dan *Diffusion* (penyebaran):
   - **Diffusion:** Disediakan oleh `ShiftRows` dan `MixColumns`, memastikan satu bit masukan memengaruhi seluruh blok keluaran.
   - **Confusion:** Disediakan secara eksklusif oleh `SubBytes` (S-box), yaitu pemetaan non-linear (inversi multiplikatif pada medan hingga $\text{GF}(2^8)$ diikuti pemetaan afin biner).
   Tanpa S-box, seluruh cipher kehilangan ketahanan terhadap aljabar linear.

2. **Dekomposisi Menjadi Pemetaan Afin atas GF(2) (CWE-327):**
   Karena operasi `AddRoundKey`, `ShiftRows`, `MixColumns`, dan penjadwalan kunci `gen_keys()` hanya melibatkan XOR dan perkalian linear pada medan biner, fungsi enkripsi untuk kunci $k$ sembarang dapat diekspresikan sebagai:
   $$E_k(p) = L(p) \oplus F(k)$$
   di mana:
   - $L: \text{GF}(2)^{128} \to \text{GF}(2)^{128}$ adalah transformasi linear bijektif yang **sama sekali tidak bergantung pada kunci**.
   - $F(k)$ adalah pergeseran vektor (*affine translation*) 128-bit yang bergantung pada master key $k$.

3. **Titik Tetap Kunci Nol (*Zero-Key Fixed Point Property*):**
   Pada penjadwalan kunci `gen_keys()`, operasi rotasi kata (*rot_word*) dan pergeseran XOR pada input byte bernilai nol akan menghasilkan byte nol secara deterministik:
   $$\text{gen\_keys}(0^{32}) = [0^{32}, 0^{32}, \dots, 0^{32}]$$
   Dengan demikian, seluruh 11 kunci putaran bernilai nol ($rk_i = 0$), sehingga pergeseran kunci $F(0) = 0$.
   Hal ini membuktikan bahwa:
   $$E_0(p) = L(p) \oplus F(0) = L(p)$$
   Komponen linear $L(p)$ dapat dihitung secara langsung untuk masukan $p$ apa pun cukup dengan mengenkripsinya menggunakan kunci nol.

4. **Kriptanalisis Known-Plaintext:**
   Dari pasangan known-plaintext $(pt_1, ct_1)$:
   $$ct_1 = L(pt_1) \oplus F(k) \implies F(k) = ct_1 \oplus E_0(pt_1)$$
   Untuk ciphertext flag $ct_2$:
   $$ct_2 = L(\text{flag}) \oplus F(k) \implies L(\text{flag}) = ct_2 \oplus F(k) = ct_2 \oplus ct_1 \oplus E_0(pt_1)$$
   Karena $L$ invertibel dan $E_0(x) = L(x)$, maka fungsi dekripsi dengan kunci nol ($D_0$) merupakan invers dari $L$:
   $$\text{flag} = D_0(L(\text{flag})) = D_0(ct_2 \oplus ct_1 \oplus E_0(pt_1))$$
   Teks terang bendera dapat dipulihkan dalam 1 putaran komputasi instan tanpa memerlukan pencarian kunci $k$.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Ekstraksi Parameter Artefak `output.txt`:**
   Membaca pasangan ciphertext dari berkas artefak:
   - $pt_1 = \text{"randomdata111111"} \to \text{hex: } 72616e646f6d64617461313131313131$
   - $ct_1 = \text{d7481d89f1aaf5a857f56edd2ae8994c}$
   - $ct_2 = \text{e5506260c6369f5d948419c2955fa236}$

2. **Perhitungan Komponen Linear $E_0(pt_1)$:**
   Mengevaluasi enkripsi $pt_1$ menggunakan kunci master beranggotakan nol (`"00" * 32`):
   ```python
   zero_key = "00" * 32
   l_pt1 = enc(pt1, zero_key)
   ```

3. **Isolasi Vektor Pergeseran Kunci $F(k)$:**
   Menghitung selisih XOR antara $ct_1$ dan $L(pt_1)$:
   ```python
   fk = bxor(bytes.fromhex(ct1), bytes.fromhex(l_pt1)).hex()
   ```

4. **Inversi Transformasi Linear untuk Memulihkan Plaintext Bendera:**
   Menghilangkan bias $F(k)$ dari $ct_2$ lalu menerapkan dekripsi kunci nol $D_0$:
   ```python
   unmasked_ct2 = bxor(bytes.fromhex(ct2), bytes.fromhex(fk)).hex()
   flag_hex = dec(unmasked_ct2, zero_key)
   flag = bytes.fromhex(flag_hex).decode("utf-8")
   # Hasil: academy{spi1cy!}
   ```

5. **Submisi Token Live ke REST API CyLab:**
   Mengeksekusi skrip solver mandiri `scripts/solve_701_black_cobra_pepper.py` dengan parameter submisi resmi:
   ```bash
   python3 scripts/solve_701_black_cobra_pepper.py --submit
   ```
   Server CyLab Academy memvalidasi token dengan respons HTTP 201 Created:
   ```json
   {"user": 1072359, "challenge": 701, "flag": "academy{spi1cy!}", "correct": true, "historical": false}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{spi1cy!}`
- **Flag Komunitas:** `CTF{spi1cy!}`
- **Status Validasi:** Terverifikasi 100% via REST API `POST https://learn.cylabacademy.org/api/submissions/` (HTTP 201 Created, `correct: true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Kurikulum LKS Cyber Security (Kriptanalisis Aljabar & Prinsip SPN):**
   - Peserta LKS harus memahami pentingnya *non-linearity* dalam konstruksi cipher simetris. Ketiadaan S-box mereduksi algoritma keamanan militer menjadi sistem persamaan linear biner sederhana yang dapat dipecahkan dengan eliminasi Gauss atau pasangan known-plaintext.
   - Menguasai pemetaan afin dan kemampuan menguji sifat *avalanche effect* (*Strict Avalanche Criterion* / SAC) pada implementasi cipher kustom.

2. **Rekomendasi Mitigasi Defensif (FIPS 197 & ISO/IEC 18033-3):**
   - **Dilarang Memodifikasi Primitif Kriptografi Standar:** Jangan pernah memodifikasi, menonaktifkan, atau menyederhanakan komponen internal algoritma standar (seperti S-box AES, konstanta putaran, atau jumlah putaran) demi optimasi performa.
   - **Terapkan Pustaka Kriptografi Terakreditasi:** Selalu gunakan pustaka kriptografi yang telah tersertifikasi FIPS 140-3 atau Common Criteria (seperti OpenSSL, BoringSSL, Libsodium) alih-alih mengimplementasikan cipher simetris sendiri (*Don't Roll Your Own Crypto*).
   - **Uji Sifat Non-Linearitas & Avalanche:** Sebelum merilis protokol berbasis cipher blok, lakukan pengujian diferensial dan linearitas statistik untuk memastikan setiap perubahan 1-bit pada plaintext atau kunci menghasilkan perubahan acak pada $\approx 50\%$ bit ciphertext.
