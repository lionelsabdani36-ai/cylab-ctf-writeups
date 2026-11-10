# Writeup: basic-mod1 (Challenge ID: 253)

> Berkas writeup lengkap terstandarisasi NIST SP 800-115 & LKS berada di: `writeups/picoCTF-2022/253-basic-mod1.md`

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Modular Arithmetic & Substitution Encoding
- **Difficulty:** Medium (diff=2)
- **Author:** Will Hong
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{R0UND_N_R0UND_65371195}`

---

## Problem Statement & Scope

Diberikan sebuah berkas teks `message.txt` yang berisi deretan 22 bilangan bulat positif yang dipisahkan oleh spasi:
```text
313 396 353 161 336 73 198 406 202 285 57 346 151 332 328 216 214 70 286 360 72 216
```

Aturan dekripsi yang ditentukan:
1. Hitung operasi modulo 37 pada setiap bilangan ($r_i = n_i \pmod{37}$).
2. Petakan sisa pembagian $r_i$ ke dalam himpunan karakter 37 simbol:
   - Nilai $0 \le r_i \le 25$: Huruf alfabet kapital `A` sampai `Z`.
   - Nilai $26 \le r_i \le 35$: Digit desimal `0` sampai `9`.
   - Nilai $r_i = 36$: Karakter garis bawah `_` (*underscore*).
3. Bungkus hasil dekripsi ke dalam format bendera platform: `academy{decrypted_message}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Substitusi Monoalfabetik Tanpa Kunci Rahasia (CWE-327 / NIST SP 800-115 § 4.2):**
   - Panduan pengujian penetrasi NIST SP 800-115 § 4.2 mensyaratkan kerahasiaan berbasis algoritma terstandarisasi dengan manajemen kunci aman.
   - Skema yang digunakan pada tantangan ini adalah pemetaan modular deterministik unkeyed: $f(n) = \text{Alphabet}[n \pmod{37}]$.
   - Karena operasi modulo 37 memetakan bilangan bulat ke dalam 37 kelas kongruensi diskret tanpa melibatkan parameter rahasia (*secret key*), transformasi ini murni berfungsi sebagai pengodean (*encoding/obfuscation*) dan bukan enkripsi yang aman.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Evaluasi setiap token bilangan terhadap modulo 37.
2. Petakan sisa modulo ke dalam charset `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_`.
3. Menghasilkan teks terang: `R0UND_N_R0UND_65371195`.
4. Bungkus dengan wrapper: `academy{R0UND_N_R0UND_65371195}`.
5. Jalankan solver mandiri: `python3 scripts/solve_253_basic_mod1.py`.

---

## Flag & Verifikasi

- **Flag:** `academy{R0UND_N_R0UND_65371195}`
- **Bukti Validasi REST API:** `POST /api/submissions/` -> HTTP 201 Created (`correct: true`).
- **Matriks Pengujian Wrapper:** `academy{...}` valid (201 correct:true), `picoCTF{...}` ditolak (correct:false).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:** Pemahaman kalkulasi modular diskret dalam kriptanalisis dasar.
- **Mitigasi Defensif:** Terapkan standar NIST FIPS (seperti AES-GCM 256-bit) dengan kunci yang dikelola aman melalui KMS/HSM.
