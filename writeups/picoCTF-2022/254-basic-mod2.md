# Writeup: basic-mod2 (Challenge ID: 254)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Modular Inversion & Ring Arithmetic
- **Difficulty:** Medium (diff=2)
- **Author:** Will Hong
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{1NV3R53LY_H4RD_471A6111}`

---

## Problem Statement & Scope

Diberikan sebuah berkas teks `message.txt` yang dapat diunduh dari pustaka berkas CyLab:
`https://challenge-files.cylabacademy.net/library/4f25bc41d739375d13732691063a72f372cc433988ff76ad620c458a792b5c9e/message.txt`

Berkas berisi 23 token bilangan bulat:
`104 126 274 231 262 378 108 352 64 338 77 209 139 441 297 168 158 309 329 415 186 145 186`

Aturan dekripsi yang ditetapkan oleh pembuat tantangan:
1. Setiap bilangan direduksi modulo 41: `r = n mod 41`.
2. Hitung invers perkalian modular dari bilangan tersebut terhadap modulus 41 (`r^(-1) mod 41`), sedemikian rupa sehingga `(r * inv) mod 41 == 1`.
3. Petakan nilai invers ke dalam alfabet karakter:
   - Nilai 1 sampai 26 dipetakan ke huruf kapital `A` sampai `Z`.
   - Nilai 27 sampai 36 dipetakan ke digit angka `0` sampai `9`.
   - Nilai 37 dipetakan ke karakter garis bawah (`_`).
4. Bungkus pesan hasil dekripsi ke dalam format bendera resmi: `academy{decrypted_message}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Invers Perkalian Modular pada Lapangan Hingga GF(41) (NIST SP 800-115 § 4.2):**
   - Modulus `m = 41` adalah bilangan prima, sehingga ring bilangan bulat modular `Z/41Z` membentuk lapangan hingga (*Galois Field*) `GF(41)` atau `F_41`.
   - Pada setiap lapangan prima `F_p`, setiap elemen bukan nol `r in F_p*` memiliki tepat satu invers perkalian modular yang unik `x in F_p*` yang memenuhi kongruensi:
     `r * x = 1 (mod p)`
   - Berdasarkan Teorema Kecil Fermat (*Fermat's Little Theorem*):
     Jika `p` prima dan `gcd(r, p) == 1`, maka `r^(p-1) = 1 (mod p)`.
     Dengan mengalikan kedua ruas dengan `r^(-1)`, diperoleh formula langsung:
     `r^(-1) = r^(p-2) = r^39 (mod 41)`.
   - Pada bahasa pemrograman Python, operasi ini dieksekusi secara instan menggunakan fungsi bawaan `pow(r, -1, 41)` yang mengimplementasikan Algoritma Euclidean Diperluas (*Extended Euclidean Algorithm*).

2. **Skema Substitusi Modular Tanpa Kunci Rahasia (CWE-327):**
   - Skema ini bukanlah algoritma enkripsi modern yang aman, melainkan sebuah cipher substitusi unkeyed berbasis fungsi trapdoor-free.
   - Karena parameter modulus `41` dan fungsi pemetaan bersifat publik tanpa adanya entropi kunci privat atau kunci simetris rahasia, kerahasiaan ciphertext runtuh seketika saat dianalisis secara statis.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh berkas `message.txt` dari pustaka CDN CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/4f25bc41d739375d13732691063a72f372cc433988ff76ad620c458a792b5c9e/message.txt
   ```
2. Ekstraksi token bilangan bulat dan evaluasi modular:
   - Token 1: `104 mod 41 = 22`. Invers: `pow(22, -1, 41) = 28` -> karakter `1` (indeks 28-1=27 -> '1').
   - Token 2: `126 mod 41 = 3`. Invers: `pow(3, -1, 41) = 14` -> karakter `N` (indeks 14-1=13 -> 'N').
   - Token 3: `274 mod 41 = 28`. Invers: `pow(28, -1, 41) = 22` -> karakter `V` (indeks 22-1=21 -> 'V').
   - Token 4: `231 mod 41 = 26`. Invers: `pow(26, -1, 41) = 30` -> karakter `3` (indeks 30-1=29 -> '3').
   - Token 5: `262 mod 41 = 16`. Invers: `pow(16, -1, 41) = 18` -> karakter `R` (indeks 18-1=17 -> 'R').
   - Token 6: `378 mod 41 = 9`. Invers: `pow(9, -1, 41) = 32` -> karakter `5` (indeks 32-1=31 -> '5').
   - Lanjutkan hingga seluruh 23 token terkonversi menghasilkan string `1NV3R53LY_H4RD_471A6111`.
3. Jalankan skrip solver mandiri `scripts/solve_254_basic_mod2.py`:
   ```bash
   python3 scripts/solve_254_basic_mod2.py
   ```
   Output:
   ```text
   [*] Auditing Module 254: basic-mod2
   [*] Stage 1: Evaluating Modulo 41 Inverses on 23 Embedded Tokens...
       [+] Decoded Stream: academy{1NV3R53LY_H4RD_471A6111}
   [+] Output Flag: academy{1NV3R53LY_H4RD_471A6111}
   ```
4. Verifikasi live penyerahan token ke REST API CyLab:
   Kirim POST ke `/api/submissions/` dengan header `X-CSRFToken` dan payload `{"challenge": 254, "flag": "academy{1NV3R53LY_H4RD_471A6111}"}`. Server merespons `HTTP 201 Created` dengan `{"correct": true}`.

---

## Flag & Verifikasi

- **Platform Verified Flag:** `academy{1NV3R53LY_H4RD_471A6111}`
- **Matriks Wrapper Acceptance:**
  - `academy{1NV3R53LY_H4RD_471A6111}`: **ACCEPTED (HTTP 201 Created, correct: true)**
  - `picoCTF{1NV3R53LY_H4RD_471A6111}`: **REJECTED (HTTP 201 Created, correct: false)**
- **Audit Bukti HTTP Live:**
  ```json
  {
    "user": 1072359,
    "challenge": 254,
    "flag": "academy{1NV3R53LY_H4RD_471A6111}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi Kriptografi LKS Cyber Security:**
   - Pemahaman mendalam mengenai struktur aljabar abstrak (grup, ring, dan lapangan berhingga).
   - Penguasaan komputasi invers modular menggunakan Algoritma Euclidean Diperluas dan Teorema Kecil Fermat.
   - Kemampuan scripting Python untuk otomasi transformasi string matematis non-linear secara deterministik.
2. **Mitigasi Defensif & Hardening (NIST SP 800-115 § 4.2 / § 5):**
   - Jangan pernah menggunakan fungsi matematika reversibel tanpa parameter rahasia sebagai mekanisme perlindungan kerahasiaan data (CWE-327).
   - Untuk mengamankan data rahasia (*data-at-rest* maupun *data-in-transit*), terapkan standar enkripsi terotentikasi modern yang terstandarisasi NIST, seperti AES-256-GCM atau ChaCha20-Poly1305 dengan manajemen kunci yang aman (KMS / HSM).
