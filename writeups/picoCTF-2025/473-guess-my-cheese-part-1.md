# Writeup: Guess My Cheese (Part 1) (Challenge ID: 473)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Classical Substitution Ciphers & Linear Systems
- **Difficulty:** Medium
- **Author:** aditin
- **Event:** picoCTF 2025
- **Points:** 200
- **Flag:** `academy{ChEeSy8b0897b1}`

---

## Problem Statement & Scope
Peserta diminta membuktikan identitas asli kepada maskot Squeexy dengan mendekripsi nama keju rahasia (*secret cheese*). Layanan lab interaktif menyediakan dua fungsionalitas:
1. `(e)ncrypt a cheese` — Mengenkripsi nama keju valid dari daftar yang dikenali sistem.
2. `(g)uess my cheese` — Menebak teks asli dari keju rahasia yang telah dienkripsi.

Layanan memberikan batas toleransi interaksi sebanyak 3 kali kesempatan sebelum menutup sesi koneksi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Struktur Affine Cipher
Affine Cipher merupakan bentuk substitusi monoalfabetik klasik di mana setiap karakter direpresentasikan sebagai bilangan bulat $x \in \mathbb{Z}_m$ (untuk alfabet kapital bahasa Inggris, $m = 26$). Fungsi enkripsinya dirumuskan sebagai:
$$E(x) = (a \cdot x + b) \pmod m$$
dengan syarat $\gcd(a, m) = 1$ agar fungsi memiliki balikan perkalian modulo (*modular multiplicative inverse*) $a^{-1} \pmod m$.

Fungsi dekripsinya adalah:
$$D(y) = a^{-1} \cdot (y - b) \pmod m$$

### 2. Oracle Enkripsi & Pemulihan Kunci (Chosen-Plaintext Attack)
Karena penyerang memiliki akses ke oracle enkripsi, penyerang dapat memilih input *known plaintext* untuk mengekstrak parameter kunci rahasia $(a, b)$:
- Mengirimkan karakter `A` ($x = 0$):
  $$E(0) = (a \cdot 0 + b) \pmod{26} = b \pmod{26}$$
  Nilai $b$ diperoleh langsung dari posisi ciphertext karakter pertama.
- Mengirimkan karakter kedua dengan nilai $x_1$ (misalnya `s` dengan $x_1 = 18$ pada keju `Asiago`):
  $$E(x_1) \equiv (a \cdot x_1 + b) \pmod{26} \implies a \cdot x_1 \equiv (y_1 - b) \pmod{26}$$
  Karena $\gcd(a, 26) = 1$, nilai $a$ dapat diisolasi secara unik dengan mencari solusi modular linear.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inisialisasi Lab & Ekstraksi Parameter Oracle:**
   Luncurkan instance lab on-demand via `PUT /api/challenges/473/instance/` dan sambungkan socket ke endpoint server (`xebec.cylabacademy.net:37817`).
2. **Kueri Oracle dengan Keju Dikenal:**
   Kirim perintah `e` lalu kirim nama keju valid `Asiago`. Server merespons dengan string terenkripsi:
   ```text
   Here's your encrypted cheese: LBVLZJ
   ```
3. **Penyelesaian Sistem Kongruensi Linear:**
   - Karakter 'A' ($x=0$) menghasilkan 'L' ($y=11$) $\implies b = 11$.
   - Karakter 'S' ($x=18$) menghasilkan 'B' ($y=1$):
     $$18a + 11 \equiv 1 \pmod{26} \implies 18a \equiv -10 \equiv 16 \pmod{26}$$
     $$9a \equiv 8 \pmod{13} \implies a \equiv 8 \cdot 9^{-1} \equiv 8 \cdot 3 \equiv 24 \equiv 11 \pmod{13}$$
     Nilai ganjil yang memenuhi pada rentang $[1, 25]$ adalah $a = 11$.
4. **Dekripsi Keju Rahasia:**
   Hitung $a^{-1} = 11^{-1} \pmod{26} = 19$.
   Dekripsikan setiap huruf ciphertext keju rahasia target `JSOVUHZMVVUFMOVILJ` menghasilkan `VASTERBOTTENOSTGZV`.
5. **Penyerahan Jawaban & Pengambilan Flag:**
   Kirim perintah `g` lalu kirim `VASTERBOTTENOSTGZV`. Server mengonfirmasi kecocokan dan mencetak kunci ruangan:
   ```text
   YUM! MMMMmmmmMMMMmmmMMM!!! Yes...yesssss! That's my cheese!
   Here's the password to the cloning room: academy{ChEeSy8b0897b1}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{ChEeSy8b0897b1}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true, "status": 201}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Kelemahan Skema Monoalfabetik Linear:** Affine cipher tidak aman terhadap serangan *chosen-plaintext* maupun analisis frekuensi. Kerentanan ini mendemonstrasikan prinsip dasar kriptoanalisis di mana linearitas fungsi enkripsi menyebabkan pemulihan kunci dapat dilakukan dalam $\mathcal{O}(1)$ kueri.
- **Rekomendasi NIST SP 800-115:** Dalam pengujian penetrasi dan audit keamanan protokol otentikasi berbasis tantangan-respons (*challenge-response*), pastikan kriptografi simetris menggunakan algoritma modern berstandar FIPS (seperti AES-256 dalam mode GCM dengan IV acak dan autentikasi integritas AEAD).
