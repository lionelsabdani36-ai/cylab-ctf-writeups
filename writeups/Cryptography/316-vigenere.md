# Writeup: Vigenere (Challenge ID: 316)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Cipher Klasik
- **Difficulty:** Easy
- **Author:** picoCTF
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{D0NT_US3_V1G3N3R3_C1PH3R_y0393es7}`

---

## Problem Statement & Scope
Diberikan berkas `cipher.txt` berisi satu baris sandi `caldfow{O0NU_WQ3_G1G3O3T3_A1AH3S_a0393cd7}` dan kunci `CYLAB`. Tugas: dekripsi dengan Vigenere dan kemas dalam format flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Sand Vigenere:** Setiap huruf plainteks `P[i]` digeser oleh huruf kunci `K[i mod L]`: `C[i] = (P[i] + K[i]) mod 26`. Dekripsi: `P[i] = (C[i] − K[i]) mod 26`. Huruf besar/kecil ditangani per basis ASCII masing-masing; non-alfabet (angka, garis bawah, kurung) **dilewati tanpa memajukan indeks kunci**.
2. **Validasi Crib:** Delapan karakter pertama cipher (`caldfow{`) dengan kunci `CYLABCYL` menghasilkan `academy{` — konfirmasi instan bahwa parameter (kunci, arah, sinkronisasi) benar sebelum mendekripsi seluruh isi.
3. ***Pitfall* Klasik:** Memajukan indeks kunci untuk karakter non-alfabet menghasilkan dekripsi kacau (`O0LW_WP3...`) — sumber kegagalan paling umum pada implementasi Vigenere dadakan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh cipher:
   ```bash
   curl -sL https://challenge-files.cylabacademy.net/library/1415ede8e9f58b36fddf7b520d73c151a53ac100c7a19f9b901100d3/cipher.txt
   # caldfow{O0NU_WQ3_G1G3O3T3_A1AH3S_a0393cd7}
   ```
2. Dekripsi dengan kunci `CYLAB`, indeks kunci hanya maju pada karakter alfabet:
   ```python
   key = "CYLAB"
   out, ki = "", 0
   for ch in cipher:
       if ch.isalpha():
           base = ord('A') if ch.isupper() else ord('a')
           k = ord(key[ki % len(key)].upper()) - 65
           out += chr((ord(ch) - base - k) % 26 + base)
           ki += 1
       else:
           out += ch
   # -> academy{D0NT_US3_V1G3N3R3_C1PH3R_y0393es7}
   ```
3. Verifikasi crib: `caldfow{` → `academy{` cocok.

---

## Flag & Verifikasi
- **Flag:** `academy{D0NT_US3_V1G3N3R3_C1PH3R_y0393es7}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Selalu Uji Crib Dulu:** Awalan/akhiran format flag yang diketahui (`academy{`, `}`) adalah oracle gratis untuk memvalidasi parameter cipher sebelum komputasi penuh.
- **Sinkronisasi Kunci:** Aturan main Vigenere — non-alfabet tidak memajukan kunci. Salah di sini, seluruh pesan kacau.
- **Mitigasi:** Vigenere dengan kunci pendek yang diulang rapuh terhadap analisis Kasiski/Friedman. Gunakan cipher modern (AES-GCM, ChaCha20-Poly1305) dengan nonce unik untuk data sensitif.
