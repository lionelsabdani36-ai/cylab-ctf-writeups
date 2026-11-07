# Writeup: Play Nice (Challenge ID: 114)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Classical Substitution Ciphers (6x6 Extended Playfair Reversal)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 110
- **Author:** MADSTACKS
- **Flag:** `academy{2e71b99fd3d07af3808f8dff2652ae0e}`

---

## Problem Statement & Scope
Tantangan `Play Nice` menyajikan layanan interaktif berbasis jaringan yang mengimplementasikan variasi algoritma kriptografi klasik *Playfair Cipher*. Deskripsi tantangan menyatakan:
> "Not all ancient ciphers were so bad... The flag is not in standard format."

Pengguna diberikan berkas skrip Python implementasi enkripsi (`playfair.py`) serta akses ke soket interaktif yang menyediakan:
1. Deretan karakter alfabet matriks teracak sepanjang 36 karakter.
2. Pesan teks tersandi (*encrypted message*) yang merupakan hasil transformasi pasangan huruf (*digram substitution*).
3. Permintaan masukan teks terang asli (*plaintext message*) dalam batas waktu tertentu untuk memvalidasi keberhasilan pemecahan sandi.

Tujuan utama audit ini adalah mengevaluasi mekanika permutasi matriks $6 \times 6$, merekonstruksi fungsi inversi aturan transformasi koordinat Playfair, mengotomasi proses dekripsi bigram, serta mengekstraksi flag heksadesimal rahasia yang disimpan server.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Perluasan Matriks Sandi Playfair $6 \times 6$ (CWE-327):**
   Sandi Playfair tradisional diciptakan oleh Charles Wheatstone (1854) menggunakan kisi $5 \times 5$ (25 sel alfabet Latin, menggabungkan huruf 'I' dan 'J'). Pada tantangan ini, ukuran kisi diperluas menjadi:
   $$\text{SQUARE\_SIZE} = 6 \quad (6 \times 6 = 36 \text{ sel})$$
   Kelebihan perluasan ini adalah kemampuan memuat seluruh 26 huruf kecil alfabet Inggris (`a`–`z`) ditambah 10 angka desimal (`0`–`9`) secara lengkap tanpa memerlukan kompresi pasangan huruf identik.

2. **Pemetaan Koordinat Kisi:**
   Matriks diinisialisasi secara berurutan baris demi baris dari string kunci permutasi sepanjang 36 karakter. Setiap karakter $c$ menempati koordinat unik:
   $$(r, \text{col}) \quad \text{dengan } r, \text{col} \in \{0, 1, 2, 3, 4, 5\}$$

3. **Aturan Dekripsi Pasangan Huruf (Digram Inversion Rules):**
   Teks tersandi dibagi menjadi pasangan berurutan $(c_1, c_2)$ dengan koordinat $(r_1, \text{col}_1)$ dan $(r_2, \text{col}_2)$. Untuk membalik proses enkripsi, diterapkan aturan simetris terbalik:
   - **Kasus 1: Baris Sama ($r_1 == r_2$):**
     Pada enkripsi, karakter digeser ke kanan ($+1$). Pada dekripsi, kedua karakter digeser siklis ke **kiri**:
     $$\text{col}'_1 = (\text{col}_1 - 1) \pmod 6$$
     $$\text{col}'_2 = (\text{col}_2 - 1) \pmod 6$$
   - **Kasus 2: Kolom Sama ($\text{col}_1 == \text{col}_2$):**
     Pada enkripsi, karakter digeser ke bawah ($+1$). Pada dekripsi, kedua karakter digeser siklis ke **atas**:
     $$r'_1 = (r_1 - 1) \pmod 6$$
     $$r'_2 = (r_2 - 1) \pmod 6$$
   - **Kasus 3: Persegi Panjang Koordinat Berbeda ($r_1 \neq r_2$ dan $\text{col}_1 \neq \text{col}_2$):**
     Kedua karakter bertukar kolom pada baris masing-masing (involusi simetris identik):
     $$c'_1 = \text{Matrix}[r_1][\text{col}_2]$$
     $$c'_2 = \text{Matrix}[r_2][\text{col}_1]$$

4. **Kelemahan Kriptanalisis Sandi Klasik:**
   Meskipun Sandi Playfair lebih kuat daripada substitusi monoalfabetik sederhana (karena mengenkripsi 2 karakter sekaligus sehingga meratakan distribusi frekuensi unigram), sandi ini tetap bersifat deterministik tanpa kunci sesi dinamis, bergantung pada permutasi statis, dan rentan terhadap pemulihan aljabar matriks otomatis seketika setelah alfabet diketahui.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pengambilan Telemetri Layanan Target:**
   Koneksi jaringan menyajikan data sesi:
   ```text
   Here is the alphabet: meiktp6yh4wxruavj9no13fb8d027c5glzsq
   Here is the encrypted message: y7bcvefqecwfste224508y1ufb21ld
   What is the plaintext message?
   ```

2. **Konstruksi Matriks Grid $6 \times 6$:**
   Alfabet `meiktp6yh4wxruavj9no13fb8d027c5glzsq` dipetakan ke dalam kisi:
   ```text
   m e i k t p
   6 y h 4 w x
   r u a v j 9
   n o 1 3 f b
   8 d 0 2 7 c
   5 g l z s q
   ```

3. **Eksekusi Dekripsi Bigram Siklis:**
   Pecah ciphertext `y7bcvefqecwfste224508y1ufb21ld` menjadi pasangan bigram:
   `('y','7'), ('b','c'), ('v','e'), ('f','q'), ('e','c'), ('w','f'), ('s','t'), ('e','2'), ('2','4'), ('5','0'), ('8','y'), ('1','u'), ('f','b'), ('2','1'), ('l','d')`
   Menerapkan aturan inversi di atas menghasilkan teks terang:
   ```text
   wd9bukbspdtj7skd3kl8d6oa3f03g0
   ```

4. **Pengiriman Teks Terang & Ekstraksi Flag:**
   Mengirimkan jawaban `wd9bukbspdtj7skd3kl8d6oa3f03g0` ke terminal server mengembalikan respons sukses:
   ```text
   Congratulations! Here's the flag: 2e71b99fd3d07af3808f8dff2652ae0e
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{2e71b99fd3d07af3808f8dff2652ae0e}`
- **Native Platform Flag:** `2e71b99fd3d07af3808f8dff2652ae0e` (format heksadesimal mentah tanpa prefix `picoCTF{}`)
- **Status Solver:** Teruji dan terverifikasi penuh melalui model reproduksi deterministik `scripts/solve_114_play_nice.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Evaluasi Keusangan Sandi Manual (Legacy Cipher Insecurity):**
   Sandi substitusi manual seperti Playfair, Vigenère, Caesar, dan Hill tidak memenuhi standar keamanan modern. Sandi-sandi ini hanya relevan untuk edukasi sejarah kriptografi dan studi pemecahan teka-teki CTF.

2. **Kepatuhan Protokol Enkripsi Modern:**
   Dalam standar industri dan perlindungan data sensitif LKS Cyber Security, seluruh data wajib dienkripsi menggunakan algoritma berbasis standar FIPS seperti **AES-256** (FIPS 197) dengan mode operasi terotentikasi (GCM atau ChaCha20-Poly1305 / RFC 8439) yang menjamin kerahasiaan (*confidentiality*), keaslian data (*authenticity*), serta ketahanan dari manipulasi teks sandi (*integrity*).
