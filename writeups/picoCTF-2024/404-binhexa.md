# Writeup: binhexa (Challenge ID: 404)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Bitwise Arithmetic & Hexadecimal Conversion
- **Difficulty:** Easy
- **Author:** Nana Ama Atombo-Sackey
- **Event:** picoCTF 2024
- **Points:** 100
- **Flag:** `academy{b1tw^3se_0p3eR@tI0n_su33essFuL_e453a847}`

---

## Problem Statement & Scope
Diberikan sebuah layanan kuis interaktif berbasis soket TCP yang menguji kemampuan operasi biner dan manipulasi bit. Pengguna diberikan 2 bilangan biner awal dan diminta menyelesaikan 6 pertanyaan kalkulasi biner berurutan sebelum memberikan representasi heksadesimal akhir untuk memperoleh flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Operasi Logika dan Aritmatika Biner:**
   - **Bitwise AND (`&`):** Menghasilkan 1 jika kedua bit bernilai 1.
   - **Bitwise OR (`|`):** Menghasilkan 1 jika salah satu bit bernilai 1.
   - **Bitwise XOR (`^`):** Menghasilkan 1 jika kedua bit berbeda.
   - **Shift Left (`<<`):** Menggeser bit ke kiri sebanyak $k$ posisi (ekuivalen perkalian dengan $2^k$).
   - **Shift Right (`>>`):** Menggeser bit ke kanan sebanyak $k$ posisi (ekuivalen pembagian integer dengan $2^k$).
   - **Aritmatika Biner (`+`, `*`):** Penjumlahan dan perkalian standar berbasis basis 2.
2. **Konversi Format Bilangan:** Pada tahap akhir, hasil kalkulasi operasi terakhir harus dikonversi ke basis 16 (*hexadecimal*) tanpa prefiks `0x` dan tanpa angka 0 di depan (*leading zeros*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Sambungkan ke layanan target via `nc`:
   ```bash
   nc xebec.cylabacademy.net 24947
   ```
2. Baca dua bilangan biner yang diberikan:
   ```text
   Binary Number 1: 00001111 (15 desimal)
   Binary Number 2: 11100111 (231 desimal)
   ```
3. Otomasi respon untuk 6 operasi berturut-turut menggunakan Python:
   - **Operasi 1 (`>>` shift kanan num 2 sebesar 1 bit):**
     $$231 \gg 1 = 115 \rightarrow \text{1110011}_2$$
   - **Operasi 2 (`|` OR num 1 dan num 2):**
     $$15 \mid 231 = 239 \rightarrow \text{11101111}_2$$
   - **Operasi 3 (`<<` shift kiri num 1 sebesar 1 bit):**
     $$15 \ll 1 = 30 \rightarrow \text{11110}_2$$
   - **Operasi 4 (`+` penjumlahan num 1 dan num 2):**
     $$15 + 231 = 246 \rightarrow \text{11110110}_2$$
   - **Operasi 5 (`&` AND num 1 dan num 2):**
     $$15 \ \& \ 231 = 7 \rightarrow \text{111}_2$$
   - **Operasi 6 (`*` perkalian num 1 dan num 2):**
     $$15 \times 231 = 3465 \rightarrow \text{110110001001}_2$$
4. Masukkan hasil heksadesimal dari operasi terakhir:
   $$3465_{10} = \text{D89}_{16} \rightarrow \text{d89}$$
5. Server memvalidasi seluruh kalkulasi dan mencetak flag:
   ```text
   Correct answer!
   The flag is: academy{b1tw^3se_0p3eR@tI0n_su33essFuL_e453a847}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{b1tw^3se_0p3eR@tI0n_su33essFuL_e453a847}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Otomasi CLI Logic (Anti-Human Delay):** Penanganan prompt interaktif bertingkat dengan variasi tipe data memerlukan arsitektur skrip modular berbasis regex state machine.
- **Penerapan Operasi Bitwise pada Kriptografi & Shellcoding:** Logika bitwise adalah inti dari algoritma stream cipher (seperti RC4), block cipher (S-box AES), dan pembuatan shellcode bebas *null byte* (`\x00`) menggunakan XOR register.
