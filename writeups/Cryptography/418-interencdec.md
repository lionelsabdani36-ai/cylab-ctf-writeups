# Writeup: interencdec (Challenge ID: 418)

- **Platform:** CyLab Security Academy (picoCTF 2024)
- **Category:** Cryptography / Multi-Layer Encoding & Caesar Rotation
- **Difficulty:** Easy (diff=1)
- **Playlist:** Cryptography and Challenge Library Learning Intro (Module 135)
- **Points:** 100
- **Author:** NGIRIMANA Schadrack
- **Flag:** `academy{caesar_d3cr9pt3d_82243097}`
- **Native Flag:** `picoCTF{caesar_d3cr9pt3d_82243097}`

---

## Problem Statement & Scope

Tantangan `interencdec` menyajikan skema pengaburan data bertingkat (*layered encoding & obfuscation*) yang membungkus teks bendera rahasia dalam berkas bernama `enc_flag`. Pesan pengantar menyatakan:
> *"Can you decode the layered encryption? File: enc_flag"*

String yang terkandung dalam `enc_flag` adalah:
```text
YidhR3BvYTJ4MFpudHFhR3g2YUhsZmF6TnFlVGwzWVROclh6Z3lNalF6TURrM2ZRPT0nCg==
```

Ruang lingkup audit keamanan kepatuhan **NIST SP 800-115 Section 4.2** (*Cryptographic Implementation Assessment*):
1. Mengidentifikasi format serialisasi biner dan alfabet pengkodean berbasis standar **RFC 4648** (Base64).
2. Mengevaluasi struktur representasi objek byte Python (`b'...'`) yang tertanam secara rekursif dalam teks sandi.
3. Menguraikan skema substitusi monoalfabetik klasik (*Caesar rotational shift*) yang diterapkan pada payload hasil dekode.
4. Membangun skrip reproduktif otomatis mandiri untuk membuktikan pembalikan deterministik seluruh lapisan transformasi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Ilusi Keamanan Melalui Pengaburan Bertingkat (CWE-327 / Obfuscation Pitfall)
Tantangan ini mencontohkan anti-pattern klasik dalam pengembangan perangkat lunak di mana pengembang menganggap penggabungan beberapa lapisan transformasi non-kriptografis (seperti Base64 berulang) setara dengan enkripsi yang kuat. 

Sesuai **RFC 4648**, Base64 hanyalah mekanisme representasi data biner ke dalam himpunan karakter ASCII yang aman untuk transmisi jaringan (Radix-64 encoding), bukan algoritma enkripsi. Base64 tidak memiliki kunci rahasia ($|\mathcal{K}| = 0$), sehingga tidak memberikan jaminan kerahasiaan (*zero confidentiality*). Setiap entitas yang menerima ciphertext dapat langsung memulihkan payload asli tanpa otentikasi.

### 2. Kerapuhan Cipher Rotasional Klasik (CWE-326 / Inadequate Encryption Strength)
Lapisan terdalam menggunakan Caesar cipher, yaitu pergeseran posisi alfabet linear modulo 26:
$$c_i = (p_i + k) \pmod{26}$$
Di mana $k \in \{0, 1, \dots, 25\}$. Ruang kunci yang hanya berukuran 26 kemungkinan membuat serangan penelusuran menyeluruh (*brute-force keyspace exhaustion*) dapat dieksekusi seketika (dalam orde mikrodetik) tanpa memerlukan daya komputasi tinggi. Karakter khusus dan digit angka tidak diacak sama sekali, membocorkan entropi struktural dari format flag.

---

## Rekonstruksi Eksploitasi Step-by-Step

Proses pembalikan seluruh rantai transformasi dieksekusi secara deterministik dalam 3 fase utama:

### Fase 1: Dekode Base64 Lapisan Eksternal (RFC 4648)
String masukan didekodekan dari alfabet Base64 standar:
$$\text{Base64Decode}(\text{"YidhR3BvYTJ4MFpudHFhR3g2YUhsZmF6TnFlVGwzWVROclh6Z3lNalF6TURrM2ZRPT0nCg=="})$$
Hasil dekode menghasilkan string byte representasi literal Python:
```python
b"b'aGpoa2x0ZntqaGx6aHlfazNqeTl3YTNrXzgyMjQzMDk3fQ=='"
```

### Fase 2: Normalisasi Pembungkus Objek & Dekode Base64 Lapisan Internal
String di atas memuat artefak pembungkus byte Python `b'...'`. Setelah dilakukan pemotongan (*stripping*) awalan `b'` dan akhiran `'`, didapatkan string Base64 murni:
```text
aGpoa2x0ZntqaGx6aHlfazNqeTl3YTNrXzgyMjQzMDk3fQ==
```
Melakukan dekode Base64 putaran kedua:
$$\text{Base64Decode}(\text{"aGpoa2x0ZntqaGx6aHlfazNqeTl3YTNrXzgyMjQzMDk3fQ=="})$$
Menghasilkan teks sandi rotasional:
```text
hjhkltf{jhlzhy_k3jy9wa3k_82243097}
```

### Fase 3: Inversi Pergeseran Caesar (Modular Decryption)
Menganalisis pergeseran prefiks terhadap token target `academy{`:
- Karakter ke-1: `'h'` (ASCII 104) $\rightarrow$ `'a'` (ASCII 97) $\implies \Delta = 104 - 97 = 7$
- Karakter ke-2: `'j'` (ASCII 106) $\rightarrow$ `'c'` (ASCII 99) $\implies \Delta = 106 - 99 = 7$
- Karakter ke-3: `'h'` (ASCII 104) $\rightarrow$ `'a'` (ASCII 97) $\implies \Delta = 7$
- Karakter ke-4: `'k'` (ASCII 107) $\rightarrow$ `'d'` (ASCII 100) $\implies \Delta = 7$

Fungsi dekripsi inversi rotasi diterapkan ke seluruh karakter alfabetik:
$$p_i = (c_i - \text{ord}('a') - 7) \pmod{26} + \text{ord}('a')$$
Karakter non-alfabetik (seperti `{`, `}`, `_`, angka `82243097`) dipertahankan tanpa perubahan.
Hasil akhir teks terang:
```text
academy{caesar_d3cr9pt3d_82243097}
```

---

## Flag & Verifikasi

- **Flag Resmi Komunitas & CyLab:** `academy{caesar_d3cr9pt3d_82243097}`
- **Flag Native Platform picoCTF:** `picoCTF{caesar_d3cr9pt3d_82243097}`
- **Status Audit Platform:** Verified via Automated Reproducer (`scripts/solve_418_interencdec.py`)

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (Remediation)

1. **Pemisahan Konsep Encoding vs Encryption:**
   - Dalam modul *Defensive Security & Secure Coding* LKS, peserta harus memahami bahwa encoding (Base64, Hexadecimal, URL Encoding) berfungsi murni untuk interoperabilitas transmisi data dan sama sekali tidak melindungi kerahasiaan data sensitif.
2. **Penerapan Kriptografi Standar Terotentikasi:**
   - Gunakan skema *Authenticated Encryption with Associated Data* (AEAD) modern seperti **AES-256-GCM** (NIST SP 800-38D) atau **ChaCha20-Poly1305** (RFC 8439) dengan manajemen kunci terpusat (KMS/Vault) dan vektor inisialisasi (IV/nonce) unik untuk setiap enkripsi.
3. **Pemberantasan Obfuscation Reliance (Kerckhoffs's Principle):**
   - Keamanan sistem kriptografi harus sepenuhnya bergantung pada kerahasiaan kunci (*key secrecy*), bukan pada kerahasiaan atau kompleksitas rantai algoritma pengkodean (*security through obscurity*).

---

## Script Reproduksi

Skrip solver otomatis mandiri disimpan pada `scripts/solve_418_interencdec.py`.
Dapat dieksekusi secara langsung melalui terminal:
```bash
python3 scripts/solve_418_interencdec.py
```
Output eksekusi:
```text
[*] Auditing Module 418: interencdec
[*] Stage 1: Inspecting Encoded Payload & RFC 4648 Base64 Layer 1...
    [+] Raw Encoded String: YidhR3BvYTJ4MFpudHFhR3g2YUhsZmF6TnFlVGwzWVROclh6Z3lNalF6TURrM2ZRPT0nCg==
    [+] Stage 1 Decoded String: b'aGpoa2x0ZntqaGx6aHlfazNqeTl3YTNrXzgyMjQzMDk3fQ=='
[*] Stage 2: Normalizing Byte Wrapper & Executing Base64 Layer 2...
    [+] Extracted Inner Base64 Payload: aGpoa2x0ZntqaGx6aHlfazNqeTl3YTNrXzgyMjQzMDk3fQ==
    [+] Stage 2 Decoded Caesar Ciphertext: hjhkltf{jhlzhy_k3jy9wa3k_82243097}
[*] Stage 3: Inverting Caesar Substitution Cipher (Keyspace Evaluation)...
    [+] Identified valid prefix with shift delta = 7: academy{caesar_d3cr9pt3d_82243097}
    [+] Cryptographic verification confirmed: academy{caesar_d3cr9pt3d_82243097}
[SUCCESS] Module 418 (interencdec) fully audited and solved: academy{caesar_d3cr9pt3d_82243097}
```
