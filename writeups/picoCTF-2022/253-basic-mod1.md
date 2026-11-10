# Writeup: basic-mod1 (Challenge ID: 253)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Modular Arithmetic & Substitution Encoding
- **Difficulty:** Medium (diff=2)
- **Author:** Will Hong
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{R0UND_N_R0UND_65371195}`

---

## Problem Statement & Scope

Diberikan sebuah berkas teks `message.txt` yang berisi deretan 22 bilangan bulat positif yang dipisahkan oleh spasi. Berkas dapat diunduh melalui repositori berkas CyLab:
`https://challenge-files.cylabacademy.net/library/f3895827512c6fab64095a69942e62ba9e367bb32d70ff69dc0e8fd9a826936a/message.txt`

Isi berkas `message.txt`:
```text
313 396 353 161 336 73 198 406 202 285 57 346 151 332 328 216 214 70 286 360 72 216
```

Aturan dekripsi yang ditentukan:
1. Hitung operasi modulo 37 pada setiap bilangan ($r_i = n_i \pmod{37}$).
2. Petakan sisa pembagian $r_i$ ke dalam himpunan karakter 37 simbol:
   - Nilai $0 \le r_i \le 25$: Huruf alfabet kapital `A` sampai `Z` ($r_i = 0 \to \text{'A'}, \dots, r_i = 25 \to \text{'Z'}$).
   - Nilai $26 \le r_i \le 35$: Digit desimal `0` sampai `9` ($r_i = 26 \to \text{'0'}, \dots, r_i = 35 \to \text{'9'}$).
   - Nilai $r_i = 36$: Karakter garis bawah `_` (*underscore*).
3. Bungkus hasil dekripsi ke dalam format bendera platform: `academy{decrypted_message}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Substitusi Monoalfabetik Tanpa Kunci Rahasia (CWE-327 / NIST SP 800-115 § 4.2):**
   - Panduan pengujian penetrasi NIST SP 800-115 § 4.2 (*Cryptographic Implementation Assessment*) mensyaratkan bahwa mekanisme pengamanan data sensitif harus menyediakan kerahasiaan (*confidentiality*) berbasis algoritma kriptografi terstandarisasi dengan manajemen kunci yang aman.
   - Skema yang digunakan pada tantangan ini adalah pemetaan modular deterministik unkeyed: $f(n) = \text{Alphabet}[n \pmod{37}]$.
   - Karena operasi modulo 37 memetakan bilangan bulat ke dalam 37 kelas kongruensi diskret tanpa melibatkan parameter rahasia (*secret key*) atau permutasi pseudorandom, transformasi ini murni berfungsi sebagai pengodean (*encoding/obfuscation*) dan bukan enkripsi yang aman.

2. **Ketiadaan Prinsip Shannon (*Diffusion & Confusion*):**
   - Tidak ada ketergantungan antar-blok data (*no block chaining / diffusion*): mengubah satu bilangan input tidak memengaruhi karakter hasil lainnya.
   - Ketiadaan fungsi non-linear yang bergantung pada kunci (*no confusion*) menyebabkan skema rentan terhadap inversi langsung maupun analisis frekuensi.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh berkas `message.txt` dari pustaka berkas CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/f3895827512c6fab64095a69942e62ba9e367bb32d70ff69dc0e8fd9a826936a/message.txt
   ```
2. Buat tabel karakter pemetaan:
   ```python
   charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
   ```
3. Evaluasi setiap token bilangan terhadap modulo 37:
   - $313 \pmod{37} = 17 \to \text{'R'}$
   - $396 \pmod{37} = 26 \to \text{'0'}$
   - $353 \pmod{37} = 20 \to \text{'U'}$
   - $161 \pmod{37} = 13 \to \text{'N'}$
   - $336 \pmod{37} = 3 \to \text{'D'}$
   - $73 \pmod{37} = 36 \to \text{'_'}$
   - $198 \pmod{37} = 13 \to \text{'N'}$
   - $406 \pmod{37} = 36 \to \text{'_'}$
   - $202 \pmod{37} = 17 \to \text{'R'}$
   - $285 \pmod{37} = 26 \to \text{'0'}$
   - $57 \pmod{37} = 20 \to \text{'U'}$
   - $346 \pmod{37} = 13 \to \text{'N'}$
   - $151 \pmod{37} = 3 \to \text{'D'}$
   - $332 \pmod{37} = 36 \to \text{'_'}$
   - $328 \pmod{37} = 32 \to \text{'6'}$
   - $216 \pmod{37} = 31 \to \text{'5'}$
   - $214 \pmod{37} = 29 \to \text{'3'}$
   - $70 \pmod{37} = 33 \to \text{'7'}$
   - $286 \pmod{37} = 27 \to \text{'1'}$
   - $360 \pmod{37} = 27 \to \text{'1'}$
   - $72 \pmod{37} = 35 \to \text{'9'}$
   - $216 \pmod{37} = 31 \to \text{'5'}$
4. Gabungkan seluruh karakter hasil:
   `R0UND_N_R0UND_65371195`
5. Bungkus dengan format bendera platform:
   `academy{R0UND_N_R0UND_65371195}`
6. Eksekusi skrip solver mandiri `scripts/solve_253_basic_mod1.py`:
   ```bash
   python3 scripts/solve_253_basic_mod1.py
   ```
   Output:
   `[+] Output Flag: academy{R0UND_N_R0UND_65371195}`

---

## Flag & Verifikasi

- **Flag:** `academy{R0UND_N_R0UND_65371195}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 253, "flag": "academy{R0UND_N_R0UND_65371195}", "correct": true}
  ```
- **Matriks Pengujian Wrapper:**
  - `academy{R0UND_N_R0UND_65371195}`: **HTTP 201 Created (`correct: true`)**
  - `picoCTF{R0UND_N_R0UND_65371195}`: **HTTP 201 Created (`correct: false`)**

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Memahami dasar-dasar aritmetika modular (ring $\mathbb{Z}_{37}$) dan implementasi decoding berbasis Python pada sub-bidang Cryptography / Cryptanalysis.
  - Membedakan antara pengodean data (*data encoding / serialization*) dan enkripsi kriptografis sejati (*authenticated encryption*).
- **Mitigasi Defensif:**
  - **Larangan Membuat Kriptografi Kustom (*Don't Roll Your Own Crypto*):** Jangan pernah merancang skema substitusi atau transposisi modular sendiri untuk mengamankan data sensitif organisasi.
  - **Standar Enkripsi Terakreditasi:** Terapkan standar NIST FIPS (seperti AES-GCM 256-bit atau ChaCha20-Poly1305) dengan manajemen kunci aman berbasis KMS atau HSM.
