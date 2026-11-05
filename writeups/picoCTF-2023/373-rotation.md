# Writeup: rotation (Challenge ID: 373)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Caesar Cipher & Rotation Analysis
- **Difficulty:** Medium (diff=2)
- **Author:** Loic Shema
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{r0tat1on_d3crypt3d_91eddab9}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman terhadap algoritma kriptografi klasik berbasis pergeseran substitusi monoalfabetik (*rotational substitution cipher / Caesar cipher*):
> *"You will find the flag after decrypting this file. Download the encrypted flag here."*
> *Hint: Sometimes rotation is right*

Peserta diberikan satu berkas teks terenkripsi bernama `encrypted.txt` yang memuat untaian karakter terenkripsi:
```text
ikilmug{z0bib1wv_l3kzgxb3l_91mllij9}
```
Tujuan modul adalah mengidentifikasi besaran pergeseran modular ($k \in [0, 25]$) dan memulihkan teks asli (*plaintext*) secara deterministik.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Analisis Kriptografi Sesuai Standar NIST SP 800-115 & SP 800-175B:**
   - Caesar Cipher dan transformasi rotasi alfabetik ($ROT\text{-}N$) memetakan setiap alfabet terbuka $P_i$ ke alfabet sandi $C_i$ menggunakan operasi modular sederhana:
     $$C_i = (P_i + k) \pmod{26}$$
   - Karena ruang kunci (*key space*) sangat terbatas pada $|\mathcal{K}| = 26$, sandi ini rentan secara absolut terhadap serangan pencarian kunci tuntas (*exhaustive key search / brute-force attack*) yang membutuhkan maksimal 25 iterasi komputasi ($O(1)$).

2. **Penggunaan Algoritma Kriptografi Usang (CWE-327):**
   - Sandi rotasi tidak menyediakan difusi (*diffusion*) maupun konfusi (*confusion*). Struktur pembungkus token (`academy{...}`) tetap mempertahankan relasi spasial, tanda kurung kurawal, karakter garis bawah (`_`), serta angka numerik tanpa terenkripsi.
   - Dengan menganalisis karakter awal `ikilmug`:
     $$\text{ord}('i') - \text{ord}('a') = 105 - 97 = 8$$
     Pergeseran modular $k = 8$ (ke kiri, atau $k = 18$ ke kanan) langsung membongkar seluruh isi teks sandi menjadi format token yang valid.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak Berkas:**
   Unduh berkas teks terenkripsi dari server CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/545f29dd6d01fbbfe2cb0c2616132c3b10c64c676d94c9cc88d3fc15020078a2/encrypted.txt
   ```

2. **Inspeksi Muatan Ciphertext:**
   ```bash
   cat encrypted.txt
   ```
   Keluaran:
   ```text
   ikilmug{z0bib1wv_l3kzgxb3l_91mllij9}
   ```

3. **Dekripsi Pergeseran Modular via CLI:**
   Menggunakan utilitas standar Linux `tr` dengan pergeseran 8 karakter alfabet:
   ```bash
   cat encrypted.txt | tr 'i-za-hI-ZA-H' 'a-zA-Z'
   ```
   Keluaran langsung menampilkan plaintext flag:
   ```text
   academy{r0tat1on_d3crypt3d_91eddab9}
   ```

4. **Verifikasi Algoritmik Multi-Shift via Python:**
   Memvalidasi rentang pergeseran 0 hingga 25 untuk memastikan tidak ada kolisi format:
   ```python
   enc = "ikilmug{z0bib1wv_l3kzgxb3l_91mllij9}"
   for shift in range(26):
       res = "".join(chr((ord(c) - ord('a') - shift) % 26 + ord('a')) if 'a' <= c <= 'z' else c for c in enc)
       if "academy{" in res:
           print(f"[+] Key Shift {shift}: {res}")
   ```
   Keluaran:
   ```text
   [+] Key Shift 8: academy{r0tat1on_d3crypt3d_91eddab9}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{r0tat1on_d3crypt3d_91eddab9}`
- **Verifikasi API Platform:** Validasi token melalui endpoint `POST /api/submissions/` menghasilkan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 373, "flag": "academy{r0tat1on_d3crypt3d_91eddab9}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Peserta LKS modul Kriptografi & Analisis Sandi wajib mengenali struktur sandi klasik melalui analisis frekuensi atau pola *known-plaintext* (seperti prefix token `academy{` atau `picoCTF{`). Pemahaman pergeseran modular $ROT\text{-}N$ adalah prasyarat untuk menyelesaikan sandi bertingkat (misal: gabungan ROT13, Base64, dan XOR).
- **Mitigasi Defensif (Kepatuhan Standar Kriptografi Modern):**
  1. *Penghentian Penggunaan Sandi Klasik (CWE-327 Remediation):* Seluruh skema pengaburan data (*data obfuscation*) atau penyandian rotasi dilarang digunakan untuk melindungi kerahasiaan data sensitif atau kredensial.
  2. *Adopsi Enkripsi Terotentikasi (NIST FIPS 197 & SP 800-38D):* Gunakan algoritma enkripsi simetris modern yang telah diaudit secara formal, seperti AES-GCM (256-bit) atau ChaCha20-Poly1305, dengan manajemen kunci yang aman (KMS / HSM).

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_373_rotation.py`.
