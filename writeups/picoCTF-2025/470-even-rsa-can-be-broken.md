# Writeup: EVEN RSA CAN BE BROKEN??? (Challenge ID: 470)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Asymmetric Encryption & Even Modulus Factorization
- **Difficulty:** Easy
- **Author:** picoCTF Team
- **Event:** picoCTF 2025
- **Points:** 200
- **Flag:** `academy{tw0_1$_pr!m3207f407f}`

---

## Problem Statement & Scope
Layanan kriptografi menyajikan ciphertext terenkripsi RSA dengan eksponen publik $e = 65537$ dan modulus $N$. Peserta diminta melakukan dekripsi terhadap ciphertext $C$ hanya berbekal nilai publik $N$ dan $e$. Tantangan ini menguji kepekaan analitis terhadap karakteristik matematis dari modulus RSA yang dihasilkan oleh sistem.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Prinsip Keamanan Asimetris RSA (Rivest-Shamir-Adleman):**
   Keamanan algoritma RSA bergantung pada sulitnya memfaktorkan modulus komposit besar $N = p \cdot q$ menjadi dua bilangan prima besar rahasia $p$ dan $q$.
2. **Kelemahan Bilangan Genap (Even Modulus Fallacy):**
   Satu-satunya bilangan prima yang bernilai genap adalah $2$. Jika generator kunci menghasilkan nilai modulus $N$ yang genap ($N \equiv 0 \pmod 2$), maka salah satu faktor primanya secara pasti adalah:
   $$p = 2$$
   Dengan diketahuinya $p = 2$, faktor prima kedua $q$ dapat langsung dihitung secara instan menggunakan pembagian bilangan bulat:
   $$q = \frac{N}{2}$$
3. **Rekonstruksi Kunci Privat:**
   Setelah faktor $p$ dan $q$ teridentifikasi, nilai fungsi totient Euler $\phi(N)$ dihitung sebagai:
   $$\phi(N) = (p - 1)(q - 1) = (2 - 1)(q - 1) = q - 1$$
   Eksponen privat $d$ dihitung melalui invers modular:
   $$d \equiv e^{-1} \pmod{\phi(N)}$$
   Pesan asli diperoleh melalui operasi perpangkatan modular standar:
   $$M \equiv C^d \pmod N$$

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Luncurkan instance lab container:
   `PUT /api/challenges/470/instance/`
2. Hubungkan ke instance dan peroleh parameter $N$, $e$, dan $C$:
   ```bash
   nc chatelaine.cylabacademy.net 31017
   ```
   Server mencetak nilai $N$, $e$, dan ciphertext.
3. Lakukan pengujian paritas pada modulus $N$:
   ```python
   assert N % 2 == 0  # N bernilai genap!
   ```
4. Faktorkan $N$ dan hitung kunci privat $d$:
   ```python
   p = 2
   q = N // 2
   phi = (p - 1) * (q - 1)
   d = pow(e, -1, phi)
   m = pow(C, d, N)
   flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
   print("Flag:", flag.decode())
   ```
5. Hasil dekripsi menghasilkan token flag:
   `academy{tw0_1$_pr!m3207f407f}`.

---

## Flag & Verifikasi
- **Flag:** `academy{tw0_1$_pr!m3207f407f}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Validasi Generator Bilangan Prima (Cryptographically Secure Prime Generation):** Pastikan pustaka kriptografi menghasilkan bilangan prima ganjil acak yang besar ($p, q \ge 2^{1024}$ untuk RSA-2048). Uji prima Miller-Rabin standar harus selalu dijalankan untuk memastikan tidak ada faktor prima kecil (terutama $p=2$) yang lolos ke proses generasi kunci.
- **Penggunaan Pustaka Standar Industri:** Jangan pernah mengimplementasikan fungsi pemilihan prima kustom (`custom get_primes`). Selalu manfaatkan modul bersertifikasi (seperti OpenSSL, PyCryptodome, atau cryptography.io) yang menerapkan pemeriksaan batas entropi dan pengujian sifat prima yang ketat.
