# Writeup: WhitePages (Challenge ID: 51)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Whitespace Steganography
- **Difficulty:** Medium
- **Author:** John Hammond
- **Event:** picoCTF 2019
- **Points:** 250
- **Flag:** `academy{not_all_spaces_are_created_equal_19fc1787ee14ef2c56ee0cddc142a0d9}`

---

## Problem Statement & Scope
Diberikan sebuah berkas teks bernama `whitepages.txt` berukuran sekitar 2.7 KB yang tampak kosong melompong ketika dibuka menggunakan text viewer biasa. Analis forensik diminta untuk mengekstraksi informasi rahasia yang tersembunyi di dalam berkas teks tersebut.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Steganografi Whitespace Karakter Unicode:**
   Teks tampak kosong karena tersusun secara eksklusif dari karakter spasi kasatmata:
   - Karakter ASCII Space (`0x20` / `\u0020`), berukuran 1 byte.
   - Karakter Unicode EM Space (`\u2003`), dienkodekan dalam UTF-8 sebagai triplet byte `0xe2 0x80 0x83` (3 byte).
2. **Kanal Tersembunyi Biner (Binary Covert Channel):**
   Dengan adanya dua simbol spasi yang berbeda secara nilai kode byte meskipun tampak identik di layar (*homoglyphic whitespace*), dokumen tersebut bertindak sebagai media steganografi biner:
   - Simbol A (ASCII Space) $\rightarrow$ merepresentasikan bit `1`
   - Simbol B (EM Space) $\rightarrow$ merepresentasikan bit `0`
   Total karakter sebanyak 1296 karakter membentuk aliran bit ($1296 \div 8 = 162$ byte) teks ASCII tersembunyi.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis distribusi byte menggunakan Python:
   ```python
   from collections import Counter
   data = open("whitepages.txt", "rb").read()
   # Ditemukan hanya 0x20 (561 kali) dan 0xe2, 0x80, 0x83 (masing-masing 735 kali)
   ```
2. Lakukan decoding biner dengan pemetaan:
   - `\u0020` (ASCII Space) $\rightarrow$ `'1'`
   - `\u2003` (EM Space) $\rightarrow$ `'0'`
3. Kelompokkan bit menjadi blok 8-bit dan konversikan ke karakter ASCII:
   ```python
   bits = "".join(['1' if ch == ' ' else '0' for ch in open("whitepages.txt", "r", encoding="utf-8").read()])
   text = bytes([int(bits[i:i+8], 2) for i in range(0, len(bits), 8)]).decode()
   ```
4. Output teks mengungkap direktori kontak publik:
   ```text
   academy

   SEE PUBLIC RECORDS & BACKGROUND REPORT
   5000 Forbes Ave, Pittsburgh, PA 15213
   academy{not_all_spaces_are_created_equal_19fc1787ee14ef2c56ee0cddc142a0d9}
   ```
5. Eksekusi solver otomatis:
   ```bash
   python3 scripts/solve_51_whitepages.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{not_all_spaces_are_created_equal_19fc1787ee14ef2c56ee0cddc142a0d9}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Deteksi Saluran Tersembunyi (Covert Channel Detection):** Pada sistem DLP (Data Loss Prevention) di industri perbankan atau pemerintahan, inspeksi dokumen wajib memeriksa variasi karakter Unicode non-standar (Zero-Width Space, Thin Space, EM Space) yang sering disalahgunakan untuk eksfiltrasi data tanpa terdeteksi oleh filter kata kunci biasa.
- **Normalisasi Teks Unicode:** Setiap input atau dokumen yang masuk ke repositori terpercaya harus melewati tahap normalisasi Unicode (NFC/NFKC) dan penolakan karakter tak kasatmata yang mencurigakan.
