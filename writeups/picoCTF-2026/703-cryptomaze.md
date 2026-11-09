# Writeup: cryptomaze (Challenge ID: 703)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / LFSR Key Derivation & AES-128 ECB
- **Difficulty:** Medium (2)
- **Points:** 100
- **Author:** Sabine Gisagara
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{scr8mbledt_flvg_cc02eb30}`
- **Flag Komunitas:** `CTF{scr8mbledt_flvg_cc02eb30}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), NIST SP 800-38A (Recommendation for Block Cipher Modes of Operation), FIPS 197 (Advanced Encryption Standard - AES), RFC 5652 (Cryptographic Message Syntax - PKCS#7), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), & CWE-330 (Use of Insufficiently Random Values).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis LKS Cyber Security `cryptomaze`, peserta diuji dalam menganalisis kelemahan perancangan generator kunci pseudorandom berbasis Linear Feedback Shift Register (LFSR) dan implementasi cipher simetris blok:
- **Skenario Lingkungan:** Diberikan berkas artefak `output.txt` yang memuat parameter internal generator bitstream dan rekaman ciphertext terenkripsi AES:
  1. Keadaan awal LFSR 64-bit (*Initial State array* beranggotakan 64 elemen biner: `state[0..63]`).
  2. Indeks tap umpan balik polinomial (*Feedback Taps*: `[63, 61, 60, 58]`).
  3. Ciphertext heksadesimal 48 byte (3 blok AES berukuran 16 byte).
- **Batasan & Arsitektur Lab:**
  1. Register beroperasi secara linear biner pada Galois Field GF(2).
  2. Penurunan kunci (*Key Derivation*) mengambil 128 bit keluaran pertama dari LFSR yang dipadatkan menjadi 16 byte (MSB-first).
  3. Enkripsi muatan menggunakan algoritma AES-128 dalam mode Electronic Codebook (ECB) dengan skema padding PKCS#7 (RFC 5652).
- **Sasaran Pengujian:**
  1. Menganalisis sifat linearitas LFSR dan mengevaluasi dampak pemaparan parameter internal state.
  2. Merekonstruksi stepping clock LFSR sepanjang 128 siklus untuk menurunkan 16-byte kunci AES-128.
  3. Mendekripsi 3 blok ciphertext ECB dan memvalidasi penghapusan padding PKCS#7.
  4. Memvalidasi token bukti penyelesaian resmi via REST API CyLab Academy (`POST /api/submissions/`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Pemaparan Parameter Internal State PRNG (CWE-330):**
   Keamanan skema kriptografi berbasis pseudorandom generator (PRNG/stream cipher) bertumpu sepenuhnya pada kerahasiaan *internal state* dan *seed*. Ketika seluruh elemen state 64-bit dan posisi tap dipublikasikan dalam artefak, entropi efektif sistem tereduksi menjadi 0 bit. Penyerang dapat memprediksi bitstream keluaran masa depan tanpa memerlukan pencarian kunci secara brute-force.

2. **Linearitas Matematis LFSR atas GF(2) (CWE-327):**
   LFSR merupakan sistem dinamik linear atas medan biner GF(2). Pada setiap siklus pergeseran $t$, bit umpan balik ($\text{fb}_t$) dihitung melalui penjumlahan modulo 2 (XOR) dari sel tap terpilih:
   $$\text{fb}_t = \bigoplus_{i \in \{63, 61, 60, 58\}} \text{state}_t[i]$$
   Bit keluaran $\text{out}_t = \text{state}_t[0]$ diekstraksi sebelum register digeser ke kiri, dan $\text{fb}_t$ disisipkan ke posisi indeks tertinggi (`state[63]`). Seluruh proses bersifat deterministik, invertibel, dan tidak memiliki komponen non-linear (*S-box/Boolean non-linear filter*), sehingga tidak memiliki ketahanan terhadap rekonstruksi analitis.

3. **Kelemahan Mode Electronic Codebook (AES-ECB, NIST SP 800-38A):**
   Penggunaan mode ECB untuk mengenkripsi beberapa blok data merupakan pelanggaran prinsip kriptografi modern:
   - Setiap blok 16-byte dienkripsi secara terpisah tanpa Initialization Vector (IV) atau chaining dependensi antar blok.
   - Blok data plaintext yang identik akan selalu menghasilkan blok ciphertext yang identik.
   - Setelah kunci 16-byte diturunkan dari LFSR, dekripsi setiap blok $C_i$ dapat dieksekusi secara independen:
     $$P_i = \text{AES-DEC}_K(C_i)$$

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Ekstraksi Parameter Artefak `output.txt`:**
   Membaca konfigurasi state 64-bit dan vektor taps `[63, 61, 60, 58]` serta ciphertext heksadesimal 48 byte:
   ```text
   5fdec2e502a7c8d5951f41da4b0e0057c0b35d156e1a3e569c6cbb212a5eb8e538338e7e04fbddef0c6260a4eb758417
   ```

2. **Simulasi Stepping LFSR Sepanjang 128 Clock:**
   Mengiterasi register sebanyak 128 putaran untuk menghasilkan 128 bit pseudorandom:
   ```python
   state = list(STATE_INIT)
   bits = []
   for _ in range(128):
       fb = state[63] ^ state[61] ^ state[60] ^ state[58]
       popped = state.pop(0)
       state.append(fb)
       bits.append(popped)
   ```

3. **Penyusunan Kunci AES-128 (Bit Packing MSB-First):**
   Mengemas setiap irisan 8-bit menjadi satu byte biner untuk membentuk kunci simetris 16-byte:
   ```python
   key_bytes = bytearray()
   for i in range(0, 128, 8):
       val = 0
       for b in bits[i:i + 8]:
           val = (val << 1) | b
       key_bytes.append(val)
   # Kunci terderivasi: 16 bytes AES key
   ```

4. **Dekripsi AES-128-ECB dan Penghapusan Padding PKCS#7:**
   Menerapkan operasi dekripsi blok ECB dan memotong byte padding standar RFC 5652:
   ```python
   cipher = AES.new(bytes(key_bytes), AES.MODE_ECB)
   pt_padded = cipher.decrypt(bytes.fromhex(ct_hex))
   pad_len = pt_padded[-1]
   flag = pt_padded[:-pad_len].decode("utf-8")
   ```

5. **Verifikasi Token Live via REST API CyLab:**
   Mengeksekusi skrip solver mandiri `scripts/solve_703_cryptomaze.py` dengan parameter submisi resmi:
   ```bash
   python3 scripts/solve_703_cryptomaze.py --submit
   ```
   Server CyLab Academy memvalidasi token dengan respons HTTP 201 Created:
   ```json
   {"user": 1072359, "challenge": 703, "flag": "academy{scr8mbledt_flvg_cc02eb30}", "correct": true, "historical": false}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{scr8mbledt_flvg_cc02eb30}`
- **Flag Komunitas:** `CTF{scr8mbledt_flvg_cc02eb30}`
- **Status Validasi:** Terverifikasi 100% via REST API `POST https://learn.cylabacademy.org/api/submissions/` (HTTP 201 Created, `correct: true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Kurikulum LKS Cyber Security (Kriptografi Terapan & Analisis PRNG):**
   - Peserta LKS harus memahami bahwa algoritma stream cipher sederhana atau LFSR murni tidak dapat digunakan langsung sebagai generator kunci kriptografis karena ketiadaan non-linearitas (*algebraic degree 1*).
   - Memahami konversi representasi bitstream ke byte stream (MSB vs LSB) dan penanganan padding PKCS#7.

2. **Rekomendasi Mitigasi Defensif (NIST SP 800-132 & NIST SP 800-38D):**
   - **Gunakan Cryptographically Secure Pseudorandom Number Generator (CSPRNG):** Untuk membangkitkan kunci enkripsi, wajib menggunakan CSPRNG yang memenuhi standar NIST SP 800-90A/B/C (seperti HMAC-DRBG, CTR-DRBG, atau `secrets`/`/dev/urandom`).
   - **Penerapan KDF Standar Industri:** Apabila kunci diturunkan dari entropi awal atau kata sandi, gunakan Key Derivation Function terstandarisasi seperti PBKDF2 (RFC 2898 / NIST SP 800-132) atau HKDF (RFC 5869) dengan garam (*salt*) unik dan jumlah iterasi memadai.
   - **Tinggalkan Mode ECB:** Gunakan mode operasi Authenticated Encryption with Associated Data (AEAD) seperti AES-GCM (NIST SP 800-38D) atau ChaCha20-Poly1305 (RFC 8439) yang memberikan kerahasiaan sekaligus jaminan integritas data otentik.
