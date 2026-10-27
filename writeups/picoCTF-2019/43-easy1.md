# Writeup: Easy1 (Challenge ID: 43)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Polyalphabetic Ciphers
- **Difficulty:** Medium
- **Author:** Alex Fulton/Danny
- **Event:** picoCTF 2019
- **Points:** 100
- **Flag:** `academy{CRYPTOISFUN}`

---

## Problem Statement & Scope
Diberikan sebuah ciphertext `UFJKXQZQUNB`, kunci enkripsi `SOLVECRYPTO`, serta tabel substitusi alfabetikal (Vigenère / One-Time Pad Table). Analis diminta untuk mendekripsikan teks sandi tersebut menjadi teks asal berhuruf kapital dan menyusunnya dalam format flag resmi `academy{...}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Prinsip Cipher Vigenère & Tabula Recta:** Enkripsi Vigenère adalah skema substitusi polialfabetik yang menggeser karakter teks terang $P_i$ berdasarkan nilai pergeseran dari karakter kunci $K_i$:
   $$C_i = (P_i + K_i) \pmod{26}$$
   Untuk membalikkan proses (dekripsi):
   $$P_i = (C_i - K_i) \pmod{26}$$
   di mana karakter `'A'` direpresentasikan sebagai 0 hingga `'Z'` sebagai 25.
2. **Kelemahan One-Time Pad Tanpa Kerahasiaan Kunci:** Secara matematis, One-Time Pad (OTP) memberikan *information-theoretic security* jika dan hanya jika kunci bersifat acak murni, berukuran sama panjang dengan pesan, tidak pernah digunakan ulang (*single-use*), dan tetap dirahasiakan. Jika kunci diketahui oleh pihak ketiga, keamanan kriptografis menjadi nol.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Pasangkan setiap karakter ciphertext dengan karakternya pada kunci:
   - $C = \text{"UFJKXQZQUNB"}$
   - $K = \text{"SOLVECRYPTO"}$
2. Lakukan operasi pengurangan modular untuk setiap indeks $i$:
   - $i=0: (\text{'U'} - \text{'S'}) = (20 - 18) \equiv 2 \pmod{26} \rightarrow \text{'C'}$
   - $i=1: (\text{'F'} - \text{'O'}) = (5 - 14) \equiv -9 \equiv 17 \pmod{26} \rightarrow \text{'R'}$
   - $i=2: (\text{'J'} - \text{'L'}) = (9 - 11) \equiv -2 \equiv 24 \pmod{26} \rightarrow \text{'Y'}$
   - $i=3: (\text{'K'} - \text{'V'}) = (10 - 21) \equiv -11 \equiv 15 \pmod{26} \rightarrow \text{'P'}$
   - $i=4: (\text{'X'} - \text{'E'}) = (23 - 4) \equiv 19 \pmod{26} \rightarrow \text{'T'}$
   - $i=5: (\text{'Q'} - \text{'C'}) = (16 - 2) \equiv 14 \pmod{26} \rightarrow \text{'O'}$
   - $i=6: (\text{'Z'} - \text{'R'}) = (25 - 17) \equiv 8 \pmod{26} \rightarrow \text{'I'}$
   - $i=7: (\text{'Q'} - \text{'Y'}) = (16 - 24) \equiv -8 \equiv 18 \pmod{26} \rightarrow \text{'S'}$
   - $i=8: (\text{'U'} - \text{'P'}) = (20 - 15) \equiv 5 \pmod{26} \rightarrow \text{'F'}$
   - $i=9: (\text{'N'} - \text{'T'}) = (13 - 19) \equiv -6 \equiv 20 \pmod{26} \rightarrow \text{'U'}$
   - $i=10: (\text{'B'} - \text{'O'}) = (1 - 14) \equiv -13 \equiv 13 \pmod{26} \rightarrow \text{'N'}$
3. Plaintext yang dihasilkan adalah: `CRYPTOISFUN`.
4. Eksekusi solver otomatis:
   ```bash
   python3 scripts/solve_43_easy1.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{CRYPTOISFUN}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Manajemen Siklus Hidup Kunci (Key Lifecycle Management):** Keamanan cipher simetris bergantung sepenuhnya pada integritas saluran distribusi kunci (*key distribution channel*). Dalam modul LKS Network Defense, kunci pre-shared wajib disimpan dalam HSM (Hardware Security Module) atau secure vault dan tidak pernah dikirimkan melalui saluran komunikasi tidak aman.
