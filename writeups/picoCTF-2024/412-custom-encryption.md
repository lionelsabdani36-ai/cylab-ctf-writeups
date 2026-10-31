# Writeup: Custom encryption (Challenge ID: 412)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Diffie-Hellman & Custom Stream Cipher
- **Difficulty:** Medium (Difficulty 2)
- **Author:** NGIRIMANA Schadrack
- **Event:** picoCTF 2024
- **Points:** 100
- **Flag:** `academy{custom_d2cr0pt6d_203edf41}`

---

## Problem Statement & Scope
Diberikan berkas implementasi enkripsi kustom `custom_encryption.py` beserta rekaman ciphertext `enc_flag` yang memuat parameter privat pertukaran kunci Diffie-Hellman ($a = 94, b = 22$) dan deretan integer hasil enkripsi. Tantangan ini menguji pemahaman analisis skema enkripsi simetris berlapis (pertukaran kunci modulo prima kecil, operasi perkalian skalar, dan transposisi reversibel XOR dinamis).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Parameter Prima Diffie-Hellman Terlalu Kecil ($p = 97$):**
   Protokol pertukaran kunci Diffie-Hellman menggunakan modulus bilangan prima $p = 97$ dan generator $g = 31$. Ruang kunci $\mathbb{F}_p^*$ hanya berukuran 96 elemen, sehingga tidak memberikan perlindungan kriptografis terhadap serangan komputasi brute-force maupun kalkulasi langsung.
2. **Keterbukaan Eksponen Privat ($a$ dan $b$):**
   File ciphertext mencatat nilai $a = 94$ dan $b = 22$ secara plaintext. Akibatnya:
   $$K_{shared} = g^{a \cdot b} \pmod p = 31^{94 \cdot 22} \pmod{97} = 81$$
   Kunci bersama dapat langsung dihitung tanpa perlu menyelesaikan masalah logaritma diskrit (*Discrete Logarithm Problem*).
3. **Invertibilitas Perkalian Linear:**
   Lapisan enkripsi kedua mengalikan nilai integer karakter dengan faktor skalar deterministik:
   $$C[i] = \text{ord}(S[i]) \times K_{shared} \times 311$$
   Karena perkalian ini dilakukan pada bilangan riil/integer tanpa reduksi modulo, proses dekripsi bersifat trivial melalui pembagian bulat:
   $$S[i] = \frac{C[i]}{K_{shared} \times 311}$$
4. **Sifat Involutori Operasi XOR:**
   Lapisan pertama membalik string awal ($\text{plaintext}[::-1]$) lalu melakukan operasi XOR per byte dengan kunci berulang `trudeau`. Karena operasi XOR bersifat self-inverse ($A \oplus B \oplus B = A$), plaintext dapat dipulihkan dengan melakukan XOR ulang menggunakan kunci yang sama dan membalikkan urutan karakter kembali ke susunan semula.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Parameter dari `enc_flag`:**
   Nilai yang diberikan:
   - $a = 94, b = 22$
   - Deret ciphertext integer: `[226719, 1687797, 1637415, ..., 0]`
2. **Kalkulasi Kunci Bersama (Shared Key):**
   ```python
   p = 97
   g = 31
   a = 94
   b = 22
   shared_key = pow(g, a * b, p)  # shared_key = 81
   factor = shared_key * 311      # factor = 25191
   ```
3. **Dekripsi Tahap 1 (Integer Division ke Semi-Cipher):**
   Bagi setiap elemen ciphertext dengan `factor`:
   ```python
   semi_cipher = "".join(chr(c // factor) for c in cipher)
   ```
4. **Dekripsi Tahap 2 (XOR Inversion & Reversal):**
   Lakukan XOR antara karakter semi-cipher dan kunci `trudeau` berulang, lalu balikkan urutan string:
   ```python
   text_key = "trudeau"
   reversed_plain = [chr(ord(c) ^ ord(text_key[i % len(text_key)])) for i, c in enumerate(semi_cipher)]
   plaintext = "".join(reversed_plain)[::-1]
   ```
5. **Eksekusi Solver:**
   Menghasilkan plaintext flag lengkap: `academy{custom_d2cr0pt6d_203edf41}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{custom_d2cr0pt6d_203edf41}`
- **Metode Verifikasi:** `POST /api/submissions/` dengan payload `{"challenge": 412, "flag": "academy{custom_d2cr0pt6d_203edf41}"}` pada REST API CyLab Security Academy. Respons server: `HTTP 201 Created` dengan `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Larangan Rolling Custom Crypto:** Modul pelatihan LKS Cyber Security menekankan kepatuhan standar industri (NIST SP 800-56A / RFC 3526). Jangan membuat algoritma pertukaran kunci kustom atau menggunakan grup modulo kecil (minimal Diffie-Hellman MODP 2048-bit atau kurva eliptik X25519).
- **Audit Kebocoran Nilai Ephemeral / Privat:** Sistem kriptografi tidak boleh mencatat parameter eksponen privat ($a, b$) ke dalam metadata output atau log produksi.
- **Konstruksi Enkripsi Terotentikasi (AEAD):** Enkripsi data simetris harus menggunakan standar modern dengan integritas terjamin (seperti AES-GCM atau ChaCha20-Poly1305) dan bukan perkalian linear atau bitwise XOR tanpa nonce/tag otentikasi.
