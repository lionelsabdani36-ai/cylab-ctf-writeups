# Writeup: john_pollard (Challenge ID: 6)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Weak RSA Key Factorization
- **Difficulty:** Medium
- **Author:** Sanjay Kannan
- **Event:** picoCTF 2019
- **Points:** 500
- **Flag:** `academy{73176001,67867967}`

---

## Problem Statement & Scope
Diberikan sebuah sertifikat digital X.509 bernama `cert`. Peserta diminta mengekstrak kunci publik RSA dari sertifikat tersebut, menemukan faktor prima modulus $N = p \times q$, dan mengirimkan flag dalam format `academy{p,q}` atau `academy{q,p}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Dasar Kriptografi RSA & Ukuran Modulus:**
   Kekuatan enkripsi RSA bertumpu pada kesulitan komputasi pemfaktoran bilangan komposit besar $N = p \cdot q$. Standar industri modern (NIST SP 800-57) menetapkan panjang kunci minimum sebesar 2048 bit (atau 3072 bit untuk jangka panjang).
2. **Kelemahan Kunci Berukuran Sangat Pendek (53-bit Modulus):**
   Pada sertifikat tantangan ini, pembacaan struktur ASN.1 mengungkap modulus:
   $$N = 4966306421059967 \quad (\approx 53\text{ bit})$$
   Ukuran modulus sebesar 53 bit dapat difaktorkan secara instan menggunakan pembagian coba-coba (*trial division*), algoritma Pollard's $p-1$, atau Pollard's $\rho$ dalam hitungan milidetik pada CPU modern, karena:
   $$\sqrt{N} \approx 70{,}472{,}025$$
   Hanya membutuhkan maksimal $7 \times 10^7$ operasi pembagian sederhana.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis sertifikat menggunakan `openssl`:
   ```bash
   openssl x509 -in cert -text -noout
   ```
   Ditemukan informasi kunci publik:
   - Modulus: `4966306421059967` (`0x11a4d45212b17f`)
   - Exponent: `65537` (`0x10001`)
2. Lakukan faktorisasi bilangan bulat di Python:
   ```python
   import math
   n = 4966306421059967
   for i in range(2, int(math.isqrt(n)) + 1):
       if n % i == 0:
           p, q = i, n // i
           print(f"Factors: {p}, {q}")
           break
   # Output: p = 67867967, q = 73176001
   ```
3. Verifikasi sifat prima:
   - $67867967 \times 73176001 = 4966306421059967$
4. Format flag: `academy{73176001,67867967}`.
5. Eksekusi skrip otomasi:
   ```bash
   python3 scripts/solve_6_john_pollard.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{73176001,67867967}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Kebijakan Manajemen Sertifikat PKI:** Dalam konfigurasi infrastruktur Public Key Infrastructure (PKI) dan server web HTTPS, pastikan Certificate Authority (CA) menolak penerbitan sertifikat dengan panjang kunci RSA di bawah 2048 bit.
- **Pemeriksaan Kerentanan Kriptografi Otomatis:** Terapkan pemindaian SSL/TLS otomatis menggunakan `testssl.sh` atau modul Python OpenSSL untuk mendeteksi penggunaan cipher suite warisan (MD2, MD5) dan panjang modulus yang rentan terhadap faktorisasi cepat.
