# Writeup: Vigenere (Challenge ID: 316)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography
- **Difficulty:** Medium (Tier 2)
- **Event:** picoCTF 2022
- **Author:** Mubarak Mikail
- **Points:** 200
- **Flag:** `academy{D0NT_US3_V1G3N3R3_C1PH3R_y0393es7}`

---

## Problem Statement & Scope

Tantangan ini menyajikan sebuah berkas sandi terenkripsi `cipher.txt` yang memuat teks terselubung:

```text
caldfow{O0NU_WQ3_G1G3O3T3_A1AH3S_a0393cd7}
```

Peserta diberikan kunci dekripsi simetris `CYLAB` dan diinstruksikan untuk memulihkan pesan teks terbuka (plaintext) menggunakan algoritma sandi klasik *Vigenère Cipher*.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Substitusi Polialfabetik Klasik (Polyalphabetic Substitution Cipher):**
   Sandi Vigenère adalah bentuk enkripsi polialfabetik yang menerapkan deretan sandi Caesar dengan pergeseran berbeda berdasarkan huruf-huruf pada kata kunci. Pergeseran karakter teks terbuka $P_i$ menghasilkan karakter sandi $C_i$:
   $$C_i = (P_i + K_{j}) \bmod 26$$
   Sebaliknya, proses dekripsi dilakukan melalui pengurangan modular:
   $$P_i = (C_i - K_{j}) \bmod 26$$
2. **Aturan Sinkronisasi Aliran Kunci (Keystream Advancement Rule):**
   Dalam implementasi standar kompetensi keamanan siber dan CTF, indeks aliran kunci $K_j$ hanya bertambah (*advance*) ketika memproses karakter alfabetikal (`A-Z`, `a-z`). Karakter non-alfabetikal (angka `0-9`, garis bawah `_`, dan tanda kurung kurawal `{}`) dipertahankan apa adanya (*pass-through*) tanpa memajukan pointer kunci.
3. **Kerapuhan Sandi Polialfabetik Periodik (CWE-327 / NIST SP 800-115 § 4.2):**
   Karena panjang kunci sangat pendek ($L = 5$) dan kunci dibocorkan secara terbuka pada deskripsi tantangan, proses pemulihan teks terbuka bersifat instan dan deterministik dalam kompleksitas $O(N)$. Bahkan jika kunci tidak diketahui, sandi Vigenère rentan terhadap metode Kasiski Examination dan Friedman Test (Index of Coincidence) untuk memecahkan panjang kunci dan frekuensi monogram.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Kunci dan Payload Ciphertext:**
   - Kunci enkripsi: `CYLAB` (panjang $L = 5$, pergeseran huruf: $C=2, Y=24, L=11, A=0, B=1$).
   - Ciphertext: `caldfow{O0NU_WQ3_G1G3O3T3_A1AH3S_a0393cd7}`.
2. **Dekripsi Bagian Prefiks Format Bendera:**
   - `c` - 2 ('C') = `a`
   - `a` - 24 ('Y') = `c`
   - `l` - 11 ('L') = `a`
   - `d` - 0 ('A') = `d`
   - `f` - 1 ('B') = `e`
   - `o` - 2 ('C') = `m`
   - `w` - 24 ('Y') = `y`
   Prefiks `caldfow` tepat terdekripsi menjadi `academy`.
3. **Dekripsi Karakter Isi Token:**
   Karakter simbol `{`, `_`, `}`, serta digit `0`, `1`, `3`, `7`, `9` diteruskan tanpa pergeseran dan tanpa menaikkan pointer kunci. Karakter huruf didekripsi berurutan:
   - `O` - 11 ('L') = `D`
   - `0` (tetap `0`)
   - `N` - 0 ('A') = `N`
   - `U` - 1 ('B') = `T`
   - `_` (tetap `_`)
   - `W` - 2 ('C') = `U`
   - `Q` - 24 ('Y') = `S`
   - `3` (tetap `3`)
   ... Menghasilkan frasa lengkap: `D0NT_US3_V1G3N3R3_C1PH3R_y0393es7`.
4. **Rekonstruksi Token Penuh:**
   Menggabungkan prefiks dan isi menghasilkan token resmi:
   `academy{D0NT_US3_V1G3N3R3_C1PH3R_y0393es7}`.
5. **Otomasi Skrip Reproduktif:**
   Mengembangkan solver otomatis mandiri pada `scripts/solve_316_vigenere.py` yang memvalidasi pembacaan berkas atau fallback string lokal dan menyerahkan flag ke platform via REST API.

---

## Flag & Verifikasi

- **Decrypted Cleartext:** `academy{D0NT_US3_V1G3N3R3_C1PH3R_y0393es7}`
- **CyLab Accepted Flag:** `academy{D0NT_US3_V1G3N3R3_C1PH3R_y0393es7}`
- **Status Submisi REST API:** HTTP 201 Created (`correct: true`, user `1072359`, challenge 316).

Bukti respons live CyLab API:
```json
{
  "user": 1072359,
  "challenge": 316,
  "flag": "academy{D0NT_US3_V1G3N3R3_C1PH3R_y0393es7}",
  "correct": true,
  "historical": false
}
```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Prinsip Kerahasiaan Kriptografi Modern:**
   Sandi klasik berbasis pergeseran modular berulang (Vigenère) tidak memiliki sifat difusi (*avalanche effect*) dan tidak memenuhi standar keamanan modern. Pesan "D0NT_US3_V1G3N3R3_C1PH3R" secara eksplisit menegaskan bahwa kriptografi substitusi polialfabetik tidak boleh digunakan dalam transmisi data produksi.
2. **Kepatuhan Algoritma Rekomendasi NIST:**
   Terapkan cipher simetris terotentikasi berstandar FIPS 197 / NIST SP 800-38D (seperti AES-256-GCM) dengan manajemen kunci berkala menggunakan Key Derivation Functions (KDF) seperti HKDF atau PBKDF2.
3. **Poin Strategis LKS Cyber Security:**
   Saat memprogram pemecah sandi Vigenère pada babak kompetisi, pastikan penanganan kondisi karakter non-alfabetik diuji secara cermat: apakah pembuat soal memajukan indeks kunci saat menemui angka/tanda baca atau mengabaikannya.
