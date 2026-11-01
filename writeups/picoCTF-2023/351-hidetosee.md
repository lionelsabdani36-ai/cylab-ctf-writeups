# Writeup: HideToSee (Challenge ID: 351)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography & Steganography / Steghide Extraction & Atbash Cipher Decryption
- **Difficulty:** Medium
- **Author:** Sunday Jacob Nwanya
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{atbash_crack_6167bd8e}`

---

## Problem Statement & Scope
Disediakan sebuah berkas citra JPEG bernama `atbash.jpg`. Peserta diminta mengekstrak data rahasia yang tersembunyi di balik citra dan melakukan pemecahan sandi kriptografi untuk memperoleh token flag resmi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Steganografi DCT (Discrete Cosine Transform) Steghide:** Utilitas `steghide` menyembunyikan data dalam frekuensi domain koefisien DCT citra JPEG. Jika penyembunyian tidak dikonfigurasi dengan kata sandi yang kuat (atau dibiarkan menggunakan passphrase kosong/default `""`), penyerang dapat mengekstrak muatan biner (*payload*) secara langsung tanpa serangan brute-force.
2. **Substitusi Klasik Monoalfabetik (Atbash Cipher):** Payload yang diekstrak merupakan teks sandi yang dienkripsi menggunakan sandi Atbash (pembalikan alfabet: $A \leftrightarrow Z, B \leftrightarrow Y, \dots, M \leftrightarrow N$). Sandi ini rentan terhadap analisis frekuensi dan pemetaan deterministik satu-ke-satu karena mempertahankan indeks karakter secara simetris:
   $$c = (25 - p) \pmod{26}$$

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Lakukan ekstraksi data tersembunyi dari citra menggunakan `steghide`:
   ```bash
   steghide extract -sf atbash.jpg -p "" -xf extracted.txt
   cat extracted.txt
   # Output: zxzwvnb{zgyzhs_xizxp_6167yw8v}
   ```
2. Analisis pola struktur flag pada ciphertext:
   - `zxzwvnb` memiliki panjang 7 karakter yang cocok dengan format awalan `academy`.
   - `z` $\rightarrow$ `a`, `x` $\rightarrow$ `c`, `w` $\rightarrow$ `d`, `v` $\rightarrow$ `e`, `n` $\rightarrow$ `m`, `b` $\rightarrow$ `y`.
   - Hubungan simetri $25 - \text{index}$ mengonfirmasi penggunaan sandi Atbash.
3. Dekripsi seluruh bagian teks sandi:
   - `zxzwvnb` $\rightarrow$ `academy`
   - `zgyzhs` $\rightarrow$ `atbash`
   - `xizxp` $\rightarrow$ `crack`
   - `6167yw8v` $\rightarrow$ `6167bd8e`
4. Hasil dekripsi akhir membentuk flag valid:
   $$\text{Flag} = \text{academy\{atbash\_crack\_6167bd8e\}}$$

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{atbash_crack_6167bd8e}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 351, "flag": "academy{atbash_crack_6167bd8e}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Steganography Hygiene & Media Sanitization:** Pada skenario *incident response* dan pertahanan data di LKS Cyber Security, semua aset media publik harus melalui proses sanitasi (re-encoding, stripping metadata EXIF, dan requantization) untuk menghancurkan kanal tersembunyi steganografis sebelum dipublikasikan.
- **Modern Cryptography Standard:** Jangan pernah mengandalkan skema keamanan berbasis pengaburan (security through obscurity) atau sandi substitusi klasik seperti Atbash/Caesar. Gunakan algoritma enkripsi terotentikasi standar industri seperti AES-256-GCM atau ChaCha20-Poly1305.
