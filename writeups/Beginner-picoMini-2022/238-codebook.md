# Writeup: Codebook (Challenge ID: 238)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Python Scripting
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** Beginner picoMini 2022
- **Points:** 20
- **Flag:** `academy{c0d3b00k_455157_570b049a}`

---

## Problem Statement & Scope
Diberikan skrip Python `code.py` dan berkas kamus sandi `codebook.txt`. Skrip membaca buku sandi lokal untuk melakukan dekripsi XOR dan menampilkan flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Operasi Bitwise XOR Cipher:** Skrip memanfaatkan operasi XOR (`^`) antara representasi byte ciphertext dengan pola karakter pada `codebook.txt`.
2. **Ketergantungan Berkas Konfigurasi:** Skrip memerlukan dependensi berkas lokal pada direktori kerja aktif (*Current Working Directory*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh kedua berkas ke direktori yang sama:
   ```bash
   curl -sL https://challenge-files.cylabacademy.net/library/3fb494d187a470eb95bf47ca5078ef3bbb640bd1ebe57128a4e67bc861026c16/code.py -o code.py
   curl -sL https://challenge-files.cylabacademy.net/library/3fb494d187a470eb95bf47ca5078ef3bbb640bd1ebe57128a4e67bc861026c16/codebook.txt -o codebook.txt
   ```
2. Jalankan skrip Python:
   ```bash
   python3 code.py
   ```
3. Skrip memproses byte XOR dan mencetak:
   ```text
   academy{c0d3b00k_455157_570b049a}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{c0d3b00k_455157_570b049a}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Manajemen Kunci Kriptografi:** Menyimpan kunci XOR di berkas teks polos yang diletakkan berdampingan dengan skrip eksekutabel melanggar prinsip pemisahan wewenang (*separation of concerns*). Kunci enkripsi harus diisolasi dan dienkripsi saat istirahat (*at rest*).
