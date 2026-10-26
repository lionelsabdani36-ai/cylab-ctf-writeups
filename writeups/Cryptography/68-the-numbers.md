# Writeup: The Numbers (Challenge ID: 68)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Classical Substitution
- **Difficulty:** Easy
- **Author:** Danny
- **Event:** picoCTF 2019
- **Points:** 50
- **Flag:** `picoCTF{THENUMBERSMASON}`

---

## Problem Statement & Scope
Diberikan sebuah gambar `the_numbers.png` yang menampilkan deretan angka berformat tertentu dengan latar belakang noise bintik warna.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Sandi Substitusi A1Z26:** Sandi substitusi klasik paling sederhana di mana setiap huruf dalam alfabet bahasa Inggris dipetakan secara linier ke indeks bilangannya ($A=1, B=2, \dots, Z=26$).
2. **Kelemahan Ruang Kunci Linier:** Cipher ini tidak memiliki kunci acak dan sepenuhnya deterministik, sehingga mudah dipecahkan seketika dengan pemetaan indeks sederhana.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis angka pada gambar:
   - Baris 1: `16 9 3 15 3 20 6 { 20 8 5`
   - Baris 2: `14 21 13 2 5 18 19 13 1`
   - Baris 3: `19 15 14 }`
2. Konversikan setiap angka $n$ menjadi karakter alfabet menggunakan formula $chr(ord('A') + n - 1)$:
   - `16, 9, 3, 15, 3, 20, 6` $\rightarrow$ `P I C O C T F`
   - `{`
   - `20, 8, 5` $\rightarrow$ `T H E`
   - `14, 21, 13, 2, 5, 18, 19, 13, 1` $\rightarrow$ `N U M B E R S M A`
   - `19, 15, 14` $\rightarrow$ `S O N`
   - `}`
3. Diperoleh flag: `picoCTF{THENUMBERSMASON}`.

---

## Flag & Verifikasi
- **Flag:** `picoCTF{THENUMBERSMASON}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Bahaya Obfuscation Primitif:** Substitusi linier atau substitusi monoalfabetik tidak memberikan kerahasiaan (*confidentiality*) nyata. Pola frekuensi bahasa manusia dapat memecahkan sandi semacam ini dalam hitungan detik.
