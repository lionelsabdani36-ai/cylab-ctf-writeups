# Writeup: EVEN RSA CAN BE BROKEN??? (Challenge ID: 470)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Asymmetric Encryption & Even Modulus Factorization
- **Difficulty:** Easy (1)
- **Points:** 200 (CyLab) / 50 (picoCTF)
- **Author:** Michael Crotty
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{tw0_1$_pr!m3207f407f}`
- **Flag Platform Asli:** `picoCTF{tw0_1$_pr!m3207f407f}`
- **Flag Komunitas:** `CTF{tw0_1$_pr!m3207f407f}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Cryptographic Security Testing), FIPS 186-5 (Digital Signature Standard - RSA Key Generation), RFC 8017 (PKCS #1: RSA Cryptography Specifications v2.2), CWE-326 (Inadequate Encryption Strength), & CWE-327 (Use of a Broken or Risky Cryptographic Algorithm).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Applied Cryptography & Vulnerability Assessment*:
- **Skenario Tantangan:** Layanan lab menyajikan ciphertext terenkripsi algoritma asimetris RSA dengan eksponen publik standar $e = 65537$ dan modulus komposit $N$. Peserta diminta melakukan dekripsi terhadap ciphertext $C$ hanya berbekal nilai publik $N$ dan $e$. Tantangan ini menguji kepekaan analitis terhadap karakteristik matematis dari modulus RSA yang dihasilkan oleh sistem.
- **Deskripsi Soal:** *"This service provides you an encrypted flag. Can you decrypt it with just N & e? Hints: How much do we trust randomness? Notice anything interesting about N? Try comparing N across multiple requests."*
- **Batasan Lingkungan & Scope Audit:**
  1. Koneksi socket TCP on-demand CyLab (`nc host port`) yang memancarkan parameter $N$, $e$, dan $cyphertext$.
  2. Analisis matematis struktur modulus integer berukuran besar (bit length 1024-2048 bit).
  3. Verifikasi sifat keterbagian modulus tanpa ketergantungan pada algoritma faktorisasi umum yang lambat (General Number Field Sieve / Pollard rho).
  4. Rekonstruksi totient Euler $\phi(N)$ dan kalkulasi invers perkalian modular untuk memperoleh eksponen privat $d$.
  5. Verifikasi live submission melalui REST API CyLab `POST /api/submissions/` (HTTP Status 201 Created).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Prinsip Keamanan Asimetris RSA (RFC 8017 / FIPS 186-5):**
   Keamanan algoritma RSA bertumpu pada kesulitan komputasi pemfaktoran bilangan bulat (*Integer Factorization Problem*). Modulus RSA $N$ dibentuk dari perkalian dua bilangan prima rahasia:
   $$N = p \cdot q$$
   Sesuai standar FIPS 186-5 Section A.1, bilangan $p$ dan $q$ wajib berupa bilangan prima ganjil acak yang besar ($p, q > 2$, dengan perbedaan panjang bit $|p - q| > 2^{n/2 - 100}$).

2. **Akar Kerentanan Pemilihan Prima Genap (CWE-326 / CWE-327):**
   Dalam teori bilangan, satu-satunya bilangan prima genap adalah bilangan bulat $2$. Jika algoritma pemilihan prima acak pada generator kunci mengalami kegagalan sanitasi atau pengujian batas bawah (memilih dari himpunan prima $\mathbb{P}$ yang mengikutsertakan $2$), maka terdapat probabilitas terpilihnya $p = 2$.
   Akibatnya, modulus publik bernilai genap:
   $$N \equiv 0 \pmod 2$$
   Karakteristik ini merusak asumsi kekerasan kriptografis secara instan:
   - Faktor prima pertama secara deterministik diketahui: $p = 2$.
   - Faktor prima kedua $q$ dihitung dalam waktu $O(1)$ melalui pembagian bilangan bulat:
     $$q = \frac{N}{2}$$

3. **Rekonstruksi Kunci Privat & Inversi Modular:**
   Setelah faktor $p$ dan $q$ dipulihkan secara instan:
   - Nilai fungsi totient Euler $\phi(N)$ dihitung sebagai:
     $$\phi(N) = (p - 1)(q - 1) = (2 - 1)(q - 1) = q - 1 = \frac{N}{2} - 1$$
   - Eksponen privat $d$ dihitung melalui balikan perkalian modular terhadap $\phi(N)$ menggunakan Extended Euclidean Algorithm:
     $$d \equiv e^{-1} \pmod{\phi(N)}$$
   - Plaintext $M$ didekripsi secara langsung:
     $$M \equiv C^d \pmod N$$
   - Penguraian byte integer $M$ (big-endian) memunculkan token bendera dalam hitungan milidetik.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengambilan Parameter Kriptografi dari Socket Lab:**
   Membuka koneksi ke instance lab:
   ```bash
   nc chatelaine.cylabacademy.net 31017
   ```
   Layanan memancarkan nilai $N$, $e$, dan $cyphertext$.

2. **Audit Paritas Modulus $N$:**
   Memeriksa bit paling tidak signifikan (LSB) dari $N$:
   ```python
   if N % 2 == 0:
       print("[!] Modulus N adalah bilangan genap! Faktor prima trivial p = 2.")
   ```

3. **Faktorisasi Instan & Perhitungan $\phi(N)$:**
   ```python
   p = 2
   q = N // 2
   phi = (p - 1) * (q - 1)  # phi = q - 1
   ```

4. **Kalkulasi Kunci Privat $d$ & Dekripsi Pesan:**
   ```python
   d = pow(e, -1, phi)
   m = pow(C, d, N)
   flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
   flag = flag_bytes.decode("utf-8", errors="ignore")
   print(f"[+] Flag berhasil didekripsi: {flag}")
   ```

5. **Hasil Ekstraksi Token:**
   ```text
   academy{tw0_1$_pr!m3207f407f}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{tw0_1$_pr!m3207f407f}`
- **Flag Platform Asli:** `picoCTF{tw0_1$_pr!m3207f407f}`
- **Status API Verification:** `POST /api/submissions/` mengembalikan respons `HTTP 201 Created` dengan `{"correct": true, "status": "correct"}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Standarisasi Pembangkitan Bilangan Prima (FIPS 186-5 & NIST SP 800-56B Rev. 2):**
   Pada perancangan modul kriptografi, parameter bilangan prima wajib melewati pengujian ketat:
   - Menetapkan batas bawah bit acak sehingga kandidat selalu berupa bilangan ganjil besar ($p \ge 2^{1024}$).
   - Menjalankan uji keprimaan probabilistik Miller-Rabin dengan jumlah iterasi minimal sesuai rekomendasi FIPS untuk menjamin probabilitas komposit $\le 2^{-100}$.

2. **Larangan Implementasi Kriptografi Kustom (Cryptographic Agility & Proven Libraries):**
   Hindari penulisan algoritma kriptografi mandiri untuk lingkungan produksi. Gunakan pustaka standar industri (seperti OpenSSL, PyCryptodome, atau modul `cryptography` Python) yang telah melalui proses audit formal dan audit kepatuhan FIPS 140-3.
