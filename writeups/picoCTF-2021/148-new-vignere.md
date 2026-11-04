# 148 - New Vignere (Cryptography, picoCTF 2021, Hard)

## Challenge Metadata
- ID: 148 | Event: picoCTF 2021
- Category: Cryptography | Difficulty: Hard (3)
- Author: MADSTACKS
- Points: 300 Pts
- Flag: `academy{468293b06253c715005873e333d98dbc}`

## Problem Statement & Scope
Tantangan memberikan berkas skrip Python `new_vignere.py` dan sebuah ciphertext 64 karakter:
`emfakcakmklfajnnlpekfpkndlmildnmnnljenfckbalpglfnknaonebfcnodkpe`.
Deskripsi menyatakan:
*"Another slight twist on a classic, see if you can recover the flag. (Wrap with academy{})"*

Objektif audit & kriptanalisis (NIST SP 800-115 / RFC 4949 Cryptanalysis of Polyalphabetic Substitution):
Menganalisis mekanisme enkripsi polyalphabetic substitution berbasis 16-karakter alfabet, memetakan batasan struktural dari representasi biner (*nibble encoding*), merekonstruksi panjang dan nilai kunci melalui pemangkasan kandidat modular (*known plaintext nibble filtering*), mendekripsi ciphertext, dan memverifikasi flag ke platform CyLab.

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Representasi Base16 / Nibble Split:**
   Skrip menggunakan fungsi `b16_encode(plain)` di mana setiap karakter dikonversi ke representasi biner 8-bit (`{0:08b}`), lalu dibagi menjadi dua bagian 4-bit (nibble tinggi dan nibble rendah). Nilai integer 0-15 dari masing-masing nibble digunakan sebagai indeks ke dalam `ALPHABET = 'abcdefghijklmnop'`.
2. **Karakteristik Plaintext Flag:**
   Skrip membatasi karakter flag dengan asersi `all([c in "abcdef0123456789" for c in flag])` (string hexadecimal lowercase).
   Nilai ASCII untuk karakter tersebut memiliki pola deterministik:
   - Karakter `'0'` hingga `'9'` (ASCII 0x30 s.d. 0x39):
     High nibble selalu `0x3` (indeks 3 -> huruf `'d'`).
     Low nibble berkisar antara `0x0` hingga `0x9` (indeks 0-9 -> `'a'` s.d. `'j'`).
   - Karakter `'a'` hingga `'f'` (ASCII 0x61 s.d. 0x66):
     High nibble selalu `0x6` (indeks 6 -> huruf `'g'`).
     Low nibble berkisar antara `0x1` hingga `0x6` (indeks 1-6 -> `'b'` s.d. `'g'`).
   Konsekuensi matematis krusial: **Setiap elemen pada indeks genap ($2i$) dari string hasil Base16 selalu bernilai `'d'` atau `'g'`.**
3. **Pelemahan Vigenere Berbasis Karakter Genap:**
   Fungsi pergeseran didefinisikan sebagai:
   $$C[i] = (P[i] + K[i \pmod L]) \pmod{16}$$
   Dengan demikian, karakter plaintext dapat dihitung balik menggunakan:
   $$P[i] = (C[i] - K[i \pmod L]) \pmod{16}$$
   Karena $P[i] \in \{'d', 'g'\}$ untuk semua $i \equiv 0 \pmod 2$, setiap kandidat karakter kunci $k \in \text{ALPHABET}$ pada posisi $j = i \pmod L$ harus memenuhi relasi tersebut di semua indeks $i$. Jika satu saja indeks menghasilkan nilai selain `'d'` atau `'g'`, kandidat kunci tersebut gugur.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Batasan Panjang Kunci:**
   Diketahui `len(key) < 15` dan `all([k in ALPHABET for k in key])`. Kita menguji panjang kunci $L \in [1, 14]$.
2. **Pemangkasan Kandidat Kunci (Pruning Candidates):**
   Untuk setiap panjang $L$, kita iterasi tiap posisi indeks kunci $j \in [0, L-1]$:
   - Menguji ke-16 karakter (`a` s.d. `p`).
   - Memastikan bahwa untuk seluruh indeks $i \equiv j \pmod L$ di mana $i$ genap, hasil `unshift(C[i], k)` berada dalam himpunan `{'d', 'g'}`.
3. **Penyelesaian Tunggal pada $L = 9$:**
   Hanya $L = 9$ yang menghasilkan himpunan kandidat konsisten: `[2, 2, 2, 1, 1, 2, 1, 1, 1]`.
   Kombinasi Cartesian menghasilkan kunci unik: `bickhknij`.
4. **Dekripsi & Rekonstruksi Flag:**
   Menerapkan operasi balik pergeseran menggunakan kunci `bickhknij` menghasilkan Base16 string.
   Menggabungkan setiap pasangan nibble menghasilkan nilai plaintext:
   `468293b06253c715005873e333d98dbc`.
5. **Verifikasi Flag:**
   Membungkus hasil dengan format `academy{468293b06253c715005873e333d98dbc}` dan mengirim ke API `POST /api/submissions/`.

## Flag & Bukti Verifikasi
- **Flag Resmi:** `academy{468293b06253c715005873e333d98dbc}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan status `HTTP 201 Created` (`correct: true`, user `1072359`).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Akar Masalah:** Penggunaan substitusi polialfabetik klasik (Vigenere) di atas ruang kunci yang kecil ($16^{<15}$) dikombinasikan dengan ketiadaan diffusion/confusion standar. Plaintext yang memiliki entropi rendah atau format terbatas (seperti hex/ASCII) membuka celah serangan *known-plaintext/format analysis* secara instan.
- **Mitigasi Defensif:**
  1. Jangan merancang algoritma kriptografi kustom (*Don't Roll Your Own Crypto*).
  2. Gunakan algoritma enkripsi simetris modern terstandarisasi NIST (AES-GCM / ChaCha20-Poly1305) dengan panjang kunci minimal 128 atau 256 bit dan mekanisme Authenticated Encryption (AEAD).
  3. Pastikan kunci kriptografi diturunkan menggunakan KDF yang aman (HKDF / PBKDF2 / Argon2) dan memiliki tingkat entropi tinggi.
