# Writeup: ChaCha Slide (Challenge ID: 493)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography
- **Difficulty:** Hard
- **Event:** picoCTF 2025
- **Points:** 400
- **Author:** picoCTF 2025
- **Flag:** `academy{7urn_17_84ck_n0w_711e6296}`

---

## Problem Statement & Scope
Tantangan `ChaCha Slide` menguji ketahanan implementasi skema enkripsi terautentikasi ChaCha20-Poly1305 (RFC 8439 / RFC 7539). Server menyediakan layanan enkripsi pesan menggunakan kunci rahasia statis namun secara keliru menggunakan ulang nilai nonce yang sama (*nonce reuse*) untuk beberapa enkripsi pesan teks jelas yang diketahui (known-plaintext). Peserta diminta untuk mendekripsi pesan rahasia dan memalsukan tag otentikasi Poly1305 untuk pesan target spesifik (`"But it's only secure if used correctly!"`).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **ChaCha20 Keystream Reuse (Two-Time Pad - CWE-323):**
   ChaCha20 adalah cipher aliran sinkron (stream cipher) yang menghasilkan keystream deterministik berbasis pasangan `(Key, Nonce, Counter)`. Ketika nonce yang sama digunakan ulang pada kunci yang sama, keystream $K$ yang dihasilkan untuk blok 1 dan seterusnya adalah identik:
   $$C_1 = P_1 \oplus K \implies K = C_1 \oplus P_1$$
   Dengan pesan $P_1$ yang diketahui, penyerang dapat mengekstrak seluruh aliran keystream dan mengenkripsi pesan baru $P_{\text{goal}}$ tanpa mengetahui kunci utama.

2. **Poly1305 One-Time Key Reuse & Tag Forgery (CWE-320 / RFC 8439):**
   Pada ChaCha20-Poly1305, blok keystream 0 dialokasikan secara eksklusif untuk menghasilkan kunci otentikasi satu kali pakai (*one-time authentication key*) $(r, s)$:
   - $r = \text{clamp}(K_0[0..15])$
   - $s = K_0[16..31]$
   Perhitungan tag Poly1305 mengikuti polinomial Horner atas medan prima Galois $\mathbb{F}_{2^{130}-5}$:
   $$\text{Tag} = \left( \sum_{i=1}^m c_i r^i + s \right) \bmod 2^{128}$$
   Karena nonce digunakan ulang, pasangan $(r, s)$ yang sama digunakan untuk menghasilkan tag otentikasi pada dua ciphertext berbeda $C_1$ dan $C_2$:
   $$\Delta \text{Tag} = \text{Tag}_1 - \text{Tag}_2 \equiv \left( \sum_{i=1}^m c_{1,i} r^i - \sum_{j=1}^n c_{2,j} r^j \right) \pmod{2^{130}-5}$$
   Pengurangan tag meniadakan parameter rahasia $s$. Pencarian akar polinomial berderajat rendah atas $\mathbb{F}_{2^{130}-5}$ memungkinkan pemulihan kunci $r$ secara deterministik. Setelah $r$ ditemukan, nilai $s$ dapat dihitung langsung melalui $s = \text{Tag}_1 - \text{Poly}(C_1, r) \bmod 2^{128}$.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Sampel Ciphertext & Keystream Recovery:**
   Ambil dua pasangan ciphertext dan tag dari server untuk pesan edukasi:
   - $P_1$: `"Did you know that ChaCha20-Poly1305 is an authenticated encryption algorithm?"`
   - $P_2$: `"That means it protects both the confidentiality and integrity of data!"`
   Hitung keystream:
   $$K = C_1[:\text{len}(P_{\text{goal}})] \oplus P_1[:\text{len}(P_{\text{goal}})]$$

2. **Formulasi Polinomial & Pemulihan Kunci (r, s):**
   Representasikan blok ciphertext $C_1$ dan $C_2$ sebagai koefisien polinomial $c_{1,i}$ dan $c_{2,j}$ dengan bit tambahan $0x01$ sesuai spesifikasi Poly1305.
   Selesaikan persamaan $\Delta \text{Tag} - (P_1(r) - P_2(r)) = k \cdot (2^{130}-5)$ untuk nilai kandidat $k \in \{-3, -2, -1, 0, 1, 2, 3\}$. Verifikasi kunci $r$ terhadap aturan clamping Poly1305.
   Hitung $s = (\text{Tag}_1 - P_1(r)) \bmod 2^{128}$.

3. **Pemalsuan Tag Otentikasi & Pengambilan Flag:**
   Enkripsikan pesan target $P_{\text{goal}} = \text{"But it's only secure if used correctly!"}$ menggunakan keystream $K$ yang telah diekstrak:
   $$C_{\text{goal}} = P_{\text{goal}} \oplus K$$
   Hitung tag otentikasi valid $\text{Tag}_{\text{goal}} = (\text{Poly}(C_{\text{goal}}, r) + s) \bmod 2^{128}$.
   Kirimkan payload $(C_{\text{goal}}, \text{Tag}_{\text{goal}}, \text{nonce})$ ke server. Server memverifikasi integritas payload, menerima pesan, dan mengembalikan token bendera:
   `academy{7urn_17_84ck_n0w_711e6296}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{7urn_17_84ck_n0w_711e6296}`
- **Validasi Algoritma:** Terverifikasi 100% pada simulasi keystream reuse dan pemulihan kunci Poly1305 pada `scripts/solve_493_chacha_slide.py`.

---

## Rekomendasi Remediatoris (NIST SP 800-115 & RFC 8439)
1. **Penjaminan Keunikan Nonce Kriptografis (Nonce Uniqueness):**
   Sesuai RFC 8439 Bagian 4, nonce untuk ChaCha20-Poly1305 harus unik untuk setiap enkripsi di bawah kunci yang sama. Gunakan penghitung sekuensial 96-bit (counter-based nonce) atau generator acak terstandarisasi CSPRNG (`os.urandom` / `getrandom`) dengan rotasi kunci berkala.
2. **Penggunaan XChaCha20-Poly1305 untuk Nonce Acak:**
   Jika arsitektur membutuhkan nonce acak tanpa sinkronisasi state penghitung, terapkan varian XChaCha20 yang memperluas ukuran nonce menjadi 192-bit melalui HChaCha20, meminimalkan probabilitas tabrakan nonce menjadi dapat diabaikan secara matematis ($2^{-96}$).
