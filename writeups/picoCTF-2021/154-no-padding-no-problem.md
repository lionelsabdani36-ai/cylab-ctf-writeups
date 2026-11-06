# Writeup: No Padding, No Problem (Challenge ID: 154)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Asymmetric RSA
- **Difficulty:** Medium (diff=2)
- **Author:** Will Hong
- **Event:** picoCTF 2021
- **Points:** 200
- **Flag:** `academy{m4ll34bl3_rs4_d3crypt10n_n0_p4dd1ng}`

---

## Problem Statement & Scope

Tantangan ini menyajikan layanan orakel dekripsi RSA interaktif melalui koneksi jaringan:
> *"Oracles can be your best friend, they will decrypt anything, except the flag's ciphertext. How will you break it?"*

Pemain diberikan modulus publik $n$, eksponen publik $e$, serta ciphertext rahasia $c = m^e \pmod n$. Layanan mengizinkan pemain mengirimkan ciphertext apa pun untuk didekripsi, dengan satu aturan validasi: **layanan menolak mendekripsi ciphertext $c$ yang identik dengan flag**.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Textbook RSA Malleability & Multiplicative Homomorphism (CWE-327):**
   Pada implementasi RSA tanpa skema padding acak (seperti PKCS#1 v1.5 atau OAEP), operasi enkripsi RSA bersifat homomorfik terhadap perkalian:
   $$\text{Enc}(m_1) \cdot \text{Enc}(m_2) \equiv (m_1^e)(m_2^e) \equiv (m_1 \cdot m_2)^e \equiv \text{Enc}(m_1 \cdot m_2) \pmod n$$
2. **Chosen-Ciphertext Attack (CCA1):**
   Penyerang dapat memilih pengali sembarang $k > 1$ (misalnya $k = 2$), lalu menghitung ciphertext termutasi:
   $$c' \equiv c \cdot k^e \equiv (m \cdot k)^e \pmod n$$
   Karena $c' \neq c$, filter orakel mengizinkan dekripsi terhadap $c'$ dan mengembalikan:
   $$m' \equiv (c')^d \equiv ((m \cdot k)^e)^d \equiv m \cdot k \pmod n$$
3. **Rekonstruksi Plaintext Asli:**
   Dengan membagi hasil dekripsi $m'$ dengan $k$ menggunakan aritmatika modular (atau pembagian integer langsung jika $m \cdot k < n$), plaintext asli $m$ dapat dipulihkan secara penuh:
   $$m = \frac{m'}{k} \pmod n$$

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Hubungkan koneksi TCP ke layanan target dan parse nilai publik $n, e$ serta ciphertext flag $c$.
2. Pilih faktor pengali $k = 2$.
3. Hitung $c' = (c \cdot 2^e) \pmod n$.
4. Kirimkan nilai $c'$ ke endpoint orakel.
5. Tangkap plaintext respon $m'$ dari orakel.
6. Hitung $m = m' // 2$.
7. Konversi integer $m$ ke representasi byte/hex untuk memperoleh string flag asli.

---

## Flag & Verifikasi

- **Flag:** `academy{m4ll34bl3_rs4_d3crypt10n_n0_p4dd1ng}`
- **Validasi Platform:** Solved on CyLab Academy.

---

## Remediasi & Mitigasi (Perspektif Defensive LKS)

1. **Wajib Gunakan Optimal Asymmetric Encryption Padding (OAEP):**
   Jangan pernah menggunakan *textbook / unpadded RSA*. Terapkan skema padding RSA-OAEP (RFC 8017) yang menyertakan fungsi hash kriptografis dan mask generation function (MGF1) untuk menghilangkan sifat homomorfisme perkalian.
2. **Implementasi Blind Decryption Protection:**
   Orakel dekripsi dalam protokol nyata tidak boleh mengekspos dekripsi arbitrer kepada pihak tidak terotentikasi tanpa verifikasi integritas pesan (misalnya melalui skema sign-then-encrypt atau authenticated encryption).
