# Writeup: Binary Digits (Challenge ID: 698)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Data Reconstruction
- **Difficulty:** Easy
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Points:** 100
- **Flag:** `academy{h1dd3n_1n_th3_b1n4ry_6d751a5b}`

---

## Deskripsi Tantangan
> This file doesn't look like much... just a bunch of 1s and 0s. But maybe it's not just random noise. Can you recover anything meaningful from this?

---

## Analisis & Rekonstruksi Citra Digital
Berkas `digits.bin` berukuran 71.744 byte, yang berisi tepat 71.744 karakter ASCII yang seluruhnya terdiri dari angka biner `'0'` dan `'1'`.

Jumlah bit $71.744 \pmod 8 = 0$, tepat menghasilkan $71.744 / 8 = 8.968$ byte biner.
Delapan karakter awal `11111111 11011000 11111111 11100000` setara dengan `0xFF 0xD8 0xFF 0xE0`, yang merupakan file magic header untuk format JPEG (`JFIF`).

### Langkah Ekstraksi
1. Konversi bitstream ASCII menjadi byte biner dan simpan sebagai `recovered.jpg`:
   ```python
   byte_arr = bytearray(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
   with open('recovered.jpg', 'wb') as f:
       f.write(byte_arr)
   ```
2. Analisis visual citra mengekstrak string flag berwarna merah di tengah background putih:
   `academy{h1dd3n_1n_th3_b1n4ry_6d751a5b}`
