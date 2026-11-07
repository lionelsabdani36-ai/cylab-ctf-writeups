# Writeup: New Caesar (Challenge ID: 158)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Base16 Custom Substitution Caesar Cipher
- **Difficulty:** Medium (diff=2)
- **Playlist:** Cryptography and Challenge Library Learning Intro (Module 136)
- **Points:** 60
- **Author:** madStacks
- **Flag:** `academy{et_tu?_a91448ca}`
- **Native Flag:** `picoCTF{et_tu?_a91448ca}`

---

## Problem Statement & Scope
Tantangan `New Caesar` menyajikan skema kriptografi substitusi kustom yang menggabungkan pengkodean Base16 (representasi 4-bit nibble) dengan pergeseran Caesar klasik. Pengguna diberikan skrip enkripsi Python `new_caesar.py` dan string teks sandi `cbdabldadbplblcnpfpnpapapecpcn`.

Tujuan dari modul bimbingan teknis LKS ini adalah menganalisis kelemahan struktural pada algoritma enkripsi kustom, mendefinisikan ruang pencarian kunci (*key space*), merekonstruksi fungsi inversi pergeseran karakter dan penggabungan nibble (*nibble recomposition*), serta memulihkan teks terang bendera (*plaintext flag*).

Ruang lingkup audit keamanan kepatuhan **NIST SP 800-115 Section 4.2** (*Cryptographic Implementation Assessment*):
1. Verifikasi spesifikasi alfabet kriptografi: 16 karakter pertama dari huruf kecil ASCII (`a` sampai `p`), merepresentasikan nilai nibble 0 sampai 15 ($2^4 = 16$).
2. Analisis pemetaan fungsi `b16_encode`: pemisahan 8-bit byte menjadi dua bagian 4-bit (MSB dan LSB).
3. Penilaian kekuatan ruang kunci: kunci dibatasi hanya 1 karakter dari alfabet 16 huruf ($|\mathcal{K}| = 16$).
4. Implementasi pembalikan pergeseran (*Caesar unshift*) dan rekombinasi nibble menjadi karakter ASCII.
5. Penapisan hasil dekripsi berbasis validasi karakter ASCII tercetak (*printable ASCII validation*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Kunci Rahasia Berdimensi Sangat Kecil (CWE-326)
Dalam skrip `new_caesar.py`, pembangkitan kunci dibatasi oleh kondisi:
```python
assert all([k in ALPHABET for k in key])
assert len(key) == 1
```
Karena panjang kunci tepat 1 karakter dan dipilih dari alfabet 16 karakter (`abcdefghijklmnop`), ruang kunci total hanya berjumlah 16 kemungkinan. Hal ini melanggar prinsip dasar kerahasiaan kriptografi modern karena rentan terhadap serangan penelusuran menyeluruh (*brute-force key exhaustion attack*) yang dapat diselesaikan dalam hitungan milidetik.

### 2. Ketiadaan Difusi dan Konfusi yang Memadai (CWE-327)
Operasi pergeseran hanya dilakukan secara lokal pada masing-masing nibble menggunakan relasi modular:
$$c_i = (n_i + k) \pmod{16}$$
Di mana $n_i$ adalah nilai nibble dan $k$ adalah nilai pergeseran kunci. Tidak terdapat operasi difusi antar-byte atau putaran non-linear. Akibatnya, setiap pasangan karakter teks sandi dapat langsung dibalikkan secara independen untuk tiap nilai tebakan $k \in [0, 15]$.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inversi Pergeseran Caesar (Unshift):**
   Untuk setiap karakter teks sandi $c$ dan kandidat kunci $k \in [0, 15]$:
   $$n = (ord(c) - ord('a') - k) \pmod{16}$$

2. **Rekombinasi Nibble Menjadi Byte ASCII:**
   Pasangan nibble berurutan $(n_{2i}, n_{2i+1})$ digabungkan kembali menjadi nilai byte 8-bit:
   $$\text{byte} = (n_{2i} \ll 4) \mid n_{2i+1}$$
   $$\text{karakter} = \text{chr}(\text{byte})$$

3. **Penyaringan Kandidat Teks Terang:**
   Dari 16 kemungkinan nilai kunci:
   - Kunci `a`: `!0\x1b01û\x1b-õýððô/-` (Karakter kontrol / non-printable)
   - ...
   - Kunci `m`: `et_tu?_a91448ca` (Seluruhnya karakter ASCII tercetak dan memuat referensi historis Julius Caesar "Et tu, Brute?")
   - Kunci `n`: `TcNcd.NP( ##'RP` (Pola acak)

4. **Pengekstrakan Flag Resmi:**
   Membungkus teks terang ke dalam format kompetisi CyLab Academy:
   `academy{et_tu?_a91448ca}`.

---

## Rekomendasi Mitigasi & Pengerasan Keamanan (Remediation)
1. **Penggunaan Algoritma Enkripsi Terstandarisasi:**
   - Tinggalkan cipher substitusi buatan sendiri. Gunakan algoritma enkripsi simetris modern yang telah diaudit secara luas, seperti AES-GCM atau ChaCha20-Poly1305.
2. **Perluasan Panjang Kunci (Sufficient Key Length):**
   - Pastikan panjang kunci minimal 128 bit (atau 256 bit untuk keamanan jangka panjang) agar tahan terhadap serangan pencarian kunci menyeluruh (*brute-force*).
3. **Penerapan Algoritma Turunan Kunci (KDF):**
   - Jika kunci diturunkan dari frasa sandi pengguna, terapkan algoritma penurunan kunci yang tahan terhadap komputasi GPU/ASIC seperti Argon2id atau PBKDF2 dengan iterasi yang memadai.

---

## Script Reproduksi
Script solver mandiri tersedia pada berkas `scripts/solve_158_new_caesar.py`.
Jalankan verifikasi dengan perintah:
```bash
python3 scripts/solve_158_new_caesar.py
```
Hasil verifikasi mengembalikan token flag valid:
`academy{et_tu?_a91448ca}`
