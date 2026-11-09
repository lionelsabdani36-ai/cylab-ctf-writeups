# Writeup: Guess My Cheese (Part 1) (Challenge ID: 473)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Classical Substitution Ciphers & Linear Congruence Oracle Analysis
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** aditin
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{ChEeSy8b0897b1}`
- **Flag Platform Asli:** `picoCTF{ChEeSy8b0897b1}`
- **Flag Komunitas:** `CTF{ChEeSy8b0897b1}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Cryptographic Assessment & Oracle Inversion), RFC 9110 (HTTP Semantics), FIPS 140-3 (Security Requirements for Cryptographic Modules), CWE-326 (Inadequate Encryption Strength), & CWE-327 (Use of a Broken or Risky Cryptographic Algorithm).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Applied Cryptography & Cryptanalysis*:
- **Skenario Tantangan:** Layanan verifikasi identitas berbasis socket TCP meminta pengguna membuktikan bahwa mereka bukan penyusup (*imposter*) dengan mendekripsi kata sandi nama keju rahasia (*secret cheese password*) yang dienkripsi menggunakan skema cipher kustom.
- **Deskripsi Soal:** *"Try to decrypt the secret cheese password to prove you're not the imposter! Hints: Remember that cipher we devised together Squeexy? The one that incorporates your *affinity* for *linear equations*???"*
- **Batasan Lingkungan & Scope Audit:**
  1. Koneksi socket TCP interaktif ke instance on-demand CyLab (`nc host port`).
  2. Batasan kuota interaksi: Maksimal 3 kali operasi sebelum koneksi dihentikan oleh server.
  3. Menu layanan interaktif:
     - `(e)ncrypt a cheese`: Mengenkripsi nama keju valid yang terdapat pada kamus sistem.
     - `(g)uess my cheese`: Mengirimkan tebakan teks asli (*plaintext*) dari keju rahasia untuk memicu pengiriman flag.
  4. Analisis kriptanalisis berbasis *Chosen-Plaintext Attack* (CPA) untuk memulihkan kunci affine dalam 1 kueri oracle.
  5. Verifikasi live submission melalui REST API CyLab `POST /api/submissions/` (HTTP Status 201 Created).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Matematis Affine Cipher (CWE-327):**
   Affine Cipher merupakan cipher substitusi monoalfabetik klasik yang memetakan setiap indeks karakter $x \in \mathbb{Z}_m$ (untuk alfabet kapital bahasa Inggris, $m = 26$) ke karakter sandi $y \in \mathbb{Z}_m$ melalui fungsi transformasi linear:
   $$E(x) = (a \cdot x + b) \pmod{26}$$
   di mana $a, b \in \mathbb{Z}_{26}$ adalah pasangan kunci rahasia (*key pair*).
   Agar fungsi enkripsi bersifat bijektif (*one-to-one and onto*) sehingga setiap karakter sandi dapat didekripsi secara unik, pengali $a$ harus relatif prima terhadap modulus $m$, yaitu:
   $$\gcd(a, 26) = 1$$

2. **Ruang Kunci Sangat Terbatas (Inadequate Keyspace - CWE-326):**
   Jumlah elemen dalam $\mathbb{Z}_{26}$ yang relatif prima terhadap 26 dihitung menggunakan fungsi Euler Totient:
   $$\phi(26) = 26 \times \left(1 - \frac{1}{2}\right) \times \left(1 - \frac{1}{13}\right) = 26 \times \frac{1}{2} \times \frac{12}{13} = 12$$
   Himpunan nilai $a$ yang valid adalah $\{1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25\}$.
   Sementara itu, parameter pergeseran $b$ memiliki 26 kemungkinan nilai ($0 \le b < 26$).
   Total ukuran ruang kunci (*total keyspace*) hanya sebesar:
   $$|\mathcal{K}| = 12 \times 26 = 312 \text{ kemungkinan kunci}$$
   Ukuran ruang kunci 312 keadaan ini dapat diuji secara komputasional (*exhaustive brute-force*) dalam waktu kurang dari 1 milidetik pada prosesor modern mana pun.

3. **Chosen-Plaintext Attack (CPA) Oracle Inversion:**
   Karena server menyediakan oracle enkripsi `(e)ncrypt a cheese`, penyerang dapat memilih nama keju yang diketahui (*known-plaintext*) dari kamus, misalnya `Asiago`:
   - Karakter ke-0 adalah `A`, di mana indeks $x_0 = 0$:
     $$y_0 = E(0) = (a \cdot 0 + b) \pmod{26} = b \pmod{26}$$
     Dengan demikian, parameter pergeseran $b$ langsung terungkap secara trivial dari karakter pertama hasil enkripsi:
     $$b = \text{ord}(C_0) - \text{ord}('A')$$
   - Karakter ke-1 adalah `S`, di mana indeks $x_1 = 18$:
     $$y_1 = E(18) = (18a + b) \pmod{26} \implies 18a \equiv (y_1 - b) \pmod{26}$$
     Karena $\gcd(18, 26) = 2$ dan $(y_1 - b)$ bernilai genap, persamaan dapat disederhanakan dengan membagi kedua ruas dengan 2:
     $$9a \equiv \frac{y_1 - b}{2} \pmod{13}$$
     Balikan perkalian modular (*modular multiplicative inverse*) dari $9 \pmod{13}$ adalah 3 (karena $9 \times 3 = 27 = 2 \cdot 13 + 1 \equiv 1 \pmod{13}$).
     Maka pengali $a$ dihitung langsung:
     $$a \equiv 3 \times \left(\frac{y_1 - b}{2}\right) \pmod{13}$$
     Dari dua kemungkinan solusi pada rentang $[0, 25]$, hanya satu nilai ganjil yang memenuhi $\gcd(a, 26) = 1$.

4. **Inversi Dekripsi Deterministik:**
   Setelah pasangan kunci $(a, b)$ terisolasi, fungsi dekripsi dihitung menggunakan balikan modular $a^{-1} = \text{pow}(a, -1, 26)$:
   $$D(y) = a^{-1} \cdot (y - b) \pmod{26}$$
   Setiap karakter pada string ciphertext keju rahasia didekripsi secara deterministik dan dikirimkan kembali ke server untuk membuka token flag.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inisialisasi Koneksi Socket TCP:**
   Membuka koneksi ke instance lab on-demand dan membaca teks pembuka untuk mengekstrak string keju terenkripsi target:
   ```text
   The secret cheese this time is encrypted as: JSOVUHZMVVUFMOVILJ.
   What would you like to do?
   ```

2. **Kueri Oracle Enkripsi dengan Known-Plaintext:**
   Mengirimkan perintah `e` untuk memilih menu enkripsi, lalu mengirimkan nama keju valid `Asiago`:
   ```text
   Which cheese would you like to encrypt?
   > Asiago
   Here's your encrypted cheese: LBVLZJ
   ```

3. **Derivasi Parameter Kunci $(a, b)$:**
   - Karakter `A` ($x_0 = 0$) menghasilkan `L` ($y_0 = 11$) $\implies b = 11$.
   - Karakter `S` ($x_1 = 18$) menghasilkan `B` ($y_1 = 1$):
     $$18a + 11 \equiv 1 \pmod{26} \implies 18a \equiv -10 \equiv 16 \pmod{26}$$
     $$9a \equiv 8 \pmod{13} \implies a \equiv 8 \times 3 = 24 \equiv 11 \pmod{13}$$
     Nilai ganjil yang memenuhi pada rentang $[1, 25]$ adalah $a = 11$.
   - Pasangan kunci teridentifikasi: $(a = 11, b = 11)$.

4. **Kalkulasi Balikan Modular dan Dekripsi Teks Target:**
   - Menghitung $a^{-1} = 11^{-1} \pmod{26} = 19$ (karena $11 \times 19 = 209 = 8 \times 26 + 1$).
   - Mendekripsi ciphertext `JSOVUHZMVVUFMOVILJ`:
     - $J (9) \implies 19 \cdot (9 - 11) = 19 \cdot (-2) = -38 \equiv 14 \pmod{26} \implies \text{'V'}$
     - $S (18) \implies 19 \cdot (18 - 11) = 19 \cdot 7 = 133 \equiv 3 \pmod{26} \implies \text{'A'}$
     - Dilanjutkan hingga seluruh karakter menghasilkan: `VASTERBOTTENOSTGZV`.

5. **Pengiriman Tebakan dan Ekstraksi Flag:**
   Memilih menu `g` (*guess my cheese*) dan mengirimkan string `VASTERBOTTENOSTGZV`:
   ```text
   What do you think the secret cheese is?
   > VASTERBOTTENOSTGZV
   Congratulations! You guessed correctly!
   Here's the password to the cloning room: academy{ChEeSy8b0897b1}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{ChEeSy8b0897b1}`
- **Flag Platform Asli:** `picoCTF{ChEeSy8b0897b1}`
- **Status API Verification:** `POST /api/submissions/` mengembalikan respons `HTTP 201 Created` dengan `{"correct": true, "status": "correct"}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kelemahan Mendasar Transformasi Linear (CWE-327 / CWE-326):**
   Cipher substitusi monoalfabetik linear seperti Affine Cipher tidak memiliki sifat difusi (*diffusion*) dan kebingungan (*confusion*) yang diwajibkan oleh prinsip Shannon. Penyerang dapat memulihkan seluruh parameter rahasia hanya dengan satu pasang data plaintext-ciphertext yang diketahui (*known-plaintext attack*).

2. **Rekomendasi Standar Kriptografi Modern (FIPS 140-3 / NIST SP 800-175B):**
   - Tinggalkan seluruh skema cipher klasik monoalfabetik/polialfabetik untuk perlindungan kerahasiaan data.
   - Wajib gunakan cipher simetrik modern berstandar industri dengan panjang kunci minimal 128-bit atau 256-bit seperti AES-GCM (Authenticated Encryption with Associated Data - AEAD) sesuai rekomendasi RFC 5116.

3. **Perlindungan Oracle Kriptografi:**
   Jika sebuah antarmuka menyediakan layanan enkripsi publik (*encryption oracle*), pastikan protokol menerapkan pembatasan frekuensi (*rate limiting*), penambahan padding non-deterministik acak (seperti OAEP pada kriptografi asimetris), dan tidak mengekspos pemrosesan data sensitif secara linear tanpa salt/nonce unik.
