# Writeup: la cifra de (Challenge ID: 3)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Classical Cipher
- **Difficulty:** Easy
- **Author:** Alex Fulton/Daniel Tunitis
- **Event:** picoCTF 2019
- **Points:** 200
- **Flag:** `academy{h311p50_0x_u1mc3x3_b1vw3x181ag1pg}`

---

## Problem Statement & Scope
Server TCP (`nc xebec.cylabacademy.net 42479`) menyajikan pesan terenkripsi berbahasa Inggris kuno. Analisis frekuensi huruf dan pola kata menunjukkan Vigenere cipher. Tugas: pulihkan kunci dan dekripsi untuk menemukan flag tersembunyi dalam teks.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Vigenere Cipher:** Enkripsi polialfabetik `c[i] = (p[i] + k[i mod L]) mod 26`. Kunci pendek berulang sehingga panjang kunci dapat dideteksi via analisis Kasiski (jarak pola berulang) atau chi-squared per kolom.
2. **Ciphertext-Only Attack:** Karena plaintext adalah bahasa Inggris, tiap kolom hasil tebakan panjang kunci dapat diuji dengan uji kecocokan frekuensi huruf Inggris (chi-squared).
3. **Format Flag Diketahui:** Awalan `academy{` memberi oracle validasi — dekripsi benar harus memunculkan pola tersebut.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Hubungkan ke server dan simpan teks terenkripsi:
   ```bash
   nc xebec.cylabacademy.net 42479 > lacifra.txt
   ```
2. Ekstrak hanya huruf, uji panjang kunci L = 2..12 dengan chi-squared per kolom terhadap distribusi Inggris.
3. Panjang kunci terbaik L = 4 dengan kunci `FLAG`.
4. Dekripsi Vigenere dengan kunci `FLAG` — flag muncul dalam badan teks:
   ```python
   # m311a50_0x_a1rn3x3_h1ah3x181gl1ag dengan kunci FLAG ->
   # h311p50_0x_u1mc3x3_b1vw3x181ag1pg
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{h311p50_0x_u1mc3x3_b1vw3x181ag1pg}`
- **Verifikasi:** GET `/api/challenges/3/` menunjukkan `solved_by_user: true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Kasiski + Chi-Squared:** Kuasai alur standar pembobolan Vigenere — deteksi panjang kunci, pecah per kolom, uji frekuensi.
- **Selalu Uji Crib Dulu:** Awalan/akhiran format flag yang diketahui (`academy{`, `}`) adalah oracle gratis untuk memvalidasi parameter cipher sebelum komputasi penuh.
- **Mitigasi:** Jangan gunakan cipher klasik untuk data sensitif. Gunakan enkripsi modern (AES-GCM) dengan kunci yang dikelola aman.
