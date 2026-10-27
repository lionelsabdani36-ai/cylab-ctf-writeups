# Writeup: Crack the Power (Challenge ID: 522)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / RSA Low Public Exponent
- **Difficulty:** Medium
- **Event:** picoMini by CMU-Africa
- **Points:** 200
- **Flag:** `academy{t1ny_e_227220c9}`

---

## Problem Statement & Scope
Disediakan parameter enkripsi RSA dengan modulus 4096-bit dan eksponen publik kecil $e = 20$.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **RSA Direct Root Extraction:** Karena pesan plaintext $m$ berukuran relatif kecil dibandingkan modulus $n$, maka $m^{20} < n$. Akibatnya, $c = m^{20} \pmod n$ sebenarnya sama dengan nilai integer $c = m^{20}$ tanpa ada pemotongan modulo.
2. **Ketiadaan Padding:** Enkripsi textbook RSA tanpa skema padding OAEP memungkinkan ekstraksi akar langsung.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Hitung akar ke-20 dari ciphertext $c$ menggunakan binary search integer murni.
2. Konversikan integer hasil akar ke bytes ASCII untuk memulihkan flag.

---

## Flag & Verifikasi
- **Flag:** `academy{t1ny_e_227220c9}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Standardized Padding:** Wajib terapkan RSA-OAEP dan gunakan eksponen publik standar $e = 65537$.
