# Writeup: PowerAnalysis: Part 2 (Challenge ID: 365)

- **Platform:** CyLab Security Academy (picoCTF 2023)
- **Category:** Cryptography / Offline Correlation Power Analysis (CPA)
- **Difficulty:** Hard
- **Playlist:** Cryptography and Challenge Library Learning Intro (Module 144)
- **Points:** 500
- **Flag:** `academy{a202f6234c28153cf01c4dce23b7f9f5}`

---

## Deskripsi Tantangan
> This embedded system allows you to measure the power consumption of the CPU while it is running an AES encryption algorithm. However, this time you have access to only a very limited number of measurements.
> File: `traces.zip` (100 pre-collected traces)

---

## Analisis & Solusi
Diberikan 100 trace pengukuran daya berisik (`trace00.txt` s/d `trace99.txt`).
Setiap berkas berisi:
- `Plaintext`: 16 byte heksadesimal.
- `Power trace`: 2666 titik sampel integer.

### Model Korelasi Daya Pearson
Mengekstraksi seluruh trace ke dalam matriks NumPy/Python murni dan menghitung koefisien korelasi Pearson terhadap model konsumsi daya Hamming Weight:
$$\text{HW}(\text{Sbox}[P_i \oplus K_i])$$
pada rentang sampel $t \in [300, 400]$.

Hasil korelasi puncak per byte:
- Byte 0: `0xa2` (korelasi: 0.5154)
- Byte 1: `0x02` (korelasi: 0.6229)
- Byte 2: `0xf6` (korelasi: 0.6075)
- Byte 3: `0x23` (korelasi: 0.5881)
- Byte 4: `0x4c` (korelasi: 0.5913)
- Byte 5: `0x28` (korelasi: 0.6621)
- Byte 6: `0x15` (korelasi: 0.5799)
- Byte 7: `0x3c` (korelasi: 0.5903)
- Byte 8: `0xf0` (korelasi: 0.5960)
- Byte 9: `0x1c` (korelasi: 0.6135)
- Byte 10: `0x4d` (korelasi: 0.6022)
- Byte 11: `0xce` (korelasi: 0.5920)
- Byte 12: `0x23` (korelasi: 0.6206)
- Byte 13: `0xb7` (korelasi: 0.6017)
- Byte 14: `0xf9` (korelasi: 0.4821)
- Byte 15: `0xf5` (korelasi: 0.6438)

Kunci AES-128: `a202f6234c28153cf01c4dce23b7f9f5`.

Flag: `academy{a202f6234c28153cf01c4dce23b7f9f5}`.
