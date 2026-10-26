# Writeup: repetitions (Challenge ID: 371)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Nested Encoding
- **Difficulty:** Easy
- **Author:** Theoneste Byagutangaza
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{base64_n3st3d_dic0d!n8_d0wnl04d3d_c7808bff}`

---

## Problem Statement & Scope
Diberikan berkas teks `enc_flag` yang memuat teks tersandi acak alfanumerik bertingkat. Peserta diminta memulihkan teks asli flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pengkodean Base64 Bertingkat (Layered/Nested Encoding):** Base64 adalah skema pengkodean biner-ke-teks yang merepresentasikan data 6-bit dalam kumpulan 64 karakter ASCII.
2. **Kekeliruan Enkripsi vs Encoding:** Pengkodean bertingkat (encoding rekursif) sering kali disalahpahami sebagai bentuk enkripsi kuat (*security by obscurity*). Karena skema algoritma deterministik dan tidak menggunakan kunci rahasia (*symmetric key*), dekode rekursif sederhana dapat membongkar seluruh lapisan perlindungan dalam sekejap.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis berkas teks `enc_flag`:
   String diakhiri dengan padding `==`, mencirikan format Base64.
2. Lakukan iterasi decoding Base64 secara otomatis menggunakan Python:
   ```python
   import base64
   with open("enc_flag") as f:
       data = f.read().strip()
   while True:
       try:
           data = base64.b64decode(data).decode()
       except Exception:
           break
   print("Flag:", data)
   ```
3. Setelah 6 iterasi Base64 unwrapping, string plaintext flag berhasil didapatkan.

---

## Flag & Verifikasi
- **Flag:** `academy{base64_n3st3d_dic0d!n8_d0wnl04d3d_c7808bff}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Enkripsi Sejati vs Serialisasi Teks:** Jangan pernah menyamarkan data rahasia dengan wrapping encoding (Base64, Hex, URL-encode). Standar industri mengharuskan kriptografi simetris terotentikasi modern seperti AES-GCM atau ChaCha20-Poly1305 dengan pengelolaan kunci yang aman (KMS / HSM).
