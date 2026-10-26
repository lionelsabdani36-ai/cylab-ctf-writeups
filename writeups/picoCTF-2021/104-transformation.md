# Writeup: Transformation (Challenge ID: 104)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Character Encoding
- **Difficulty:** Easy
- **Author:** madStacks
- **Event:** picoCTF 2021
- **Points:** 20
- **Flag:** `academy{16_bits_inst34d_of_8_790ba37e}`

---

## Problem Statement & Scope
Diberikan berkas biner teks `enc` yang dienkripsi menggunakan satu baris kode Python:
```python
''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])
```
Peserta diminta merekonstruksi string flag asli dari representasi 16-bit karakter tersebut.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pengemasan Byte 16-bit (Two-Byte Packing):** Fungsi pembuat sandi mengambil dua karakter ASCII 8-bit berurutan ($c_1$ dan $c_2$). Karakter pertama digeser 8 bit ke kiri (`c1 << 8`), kemudian dijumlahkan dengan karakter kedua (`+ c2`), menghasilkan sebuah bilangan integer 16-bit yang dirender sebagai karakter Unicode 16-bit.
2. **Keterbalikan Operasi Bitwise (Reversibility):** Karena operasi `<< 8` dan `+` dilakukan tanpa modulasi rugi (*lossless*), byte pertama dapat dipulihkan dengan pergeseran balik ke kanan (`val >> 8`) dan byte kedua dengan operasi bitwise AND (`val & 0xFF`).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh berkas `enc` dan baca sebagai UTF-8:
2. Terapkan algoritma inversi bitwise:
   ```python
   with open("enc", "r", encoding="utf-8") as f:
       enc = f.read().strip()

   flag = ""
   for c in enc:
       val = ord(c)
       flag += chr(val >> 8) + chr(val & 0xFF)

   print("Flag:", flag)
   ```
3. Eksekusi program memulihkan seluruh teks flag:
   ```text
   academy{16_bits_inst34d_of_8_790ba37e}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{16_bits_inst34d_of_8_790ba37e}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pemahaman Representasi Memori & Endianness:** Keterampilan mengurai bitwise shift dan masking adalah pondasi utama dalam analisis protokol biner, rekayasa balik format berkas tertutup, serta eksploitasi biner pada arsitektur Little-Endian vs Big-Endian.
