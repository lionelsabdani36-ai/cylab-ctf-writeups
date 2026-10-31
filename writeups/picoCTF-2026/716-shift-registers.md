# Writeup: shift registers (Challenge ID: 716)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / LFSR & Small State Space Cryptanalysis
- **Difficulty:** Medium (Difficulty 2)
- **Author:** CyLab Security Academy
- **Event:** picoCTF 2026
- **Points:** 100
- **Flag:** `academy{l1n3ar_f33dback_sh1ft_r3g}`

---

## Problem Statement & Scope
Diberikan berkas sumber Python `chall.py` dan berkas ciphertext `output.txt` yang memuat representasi heksadesimal dari pesan terenkripsi. Skrip menghasilkan kunci acak berukuran 126 byte (`get_random_bytes(126)`), namun hanya menggunakan byte terendah (`key & 0xFF`) sebagai keadaan awal (*initial state*) dari sebuah Linear Feedback Shift Register (LFSR) 8-bit berumpan balik Galois/Fibonacci tereduksi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyempitan Entropi Kunci Kritis (*Key Space Collapse*):**
   Meskipun generator membangkitkan 126 byte acak ($126 \times 8 = 1008$ bit entropi potensial), baris inisialisasi:
   ```python
   lfsr = key & 0xFF
   ```
   memotong seluruh entropi tersebut dan hanya menyisakan 8 bit ($2^8 = 256$ kemungkinan nilai awal).
2. **Keterbatasan Ruang Keadaan LFSR 8-Bit:**
   Dengan register selebar 8 bit, periodisitas maksimum LFSR paling banyak bernilai $2^8 - 1 = 255$ siklus. Karena ruang keadaan awal hanya 256 nilai integer ($0 \le \text{init} \le 255$), pencarian menyeluruh (*exhaustive keyspace sweep*) dapat dieksekusi secara instan (< 10 ms).
3. **Linearitas Keystream Generator:**
   Operasi LFSR murni bersifat linear terhadap medan biner $\mathbb{F}_2$. Tanpa adanya komponen non-linear (*S-Box* atau *filter generator* seperti pada Grain/Trivium), aliran kunci yang dihasilkan rentan terhadap rekonstruksi parsial maupun serangan *known-plaintext* melalui algoritma Berlekamp-Massey.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Fungsi Stepping LFSR:**
   ```python
   def steplfsr(lfsr):
       b7 = (lfsr >> 7) & 1
       b5 = (lfsr >> 5) & 1
       b4 = (lfsr >> 4) & 1
       b3 = (lfsr >> 3) & 1
       feedback = b7 ^ b5 ^ b4 ^ b3
       return (feedback << 7) | (lfsr >> 1)
   ```
2. **Ekstraksi Ciphertext:**
   Ciphertext dari `output.txt` berukuran 34 byte:
   `30cbb50e507774fdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9`
3. **Pencarian Brute-Force 256 Nilai Awal:**
   Iterasikan nilai awal `init` dari 0 hingga 255. Pada setiap iterasi, bangkitkan keystream sebanyak 34 byte dan lakukan operasi XOR dengan ciphertext.
4. **Isolasi Flag:**
   Pada nilai `init = 162` (heksadesimal `0xA2`), deretan karakter yang dihasilkan membentuk pola teks ASCII valid dengan format `academy{...}`:
   `academy{l1n3ar_f33dback_sh1ft_r3g}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{l1n3ar_f33dback_sh1ft_r3g}`
- **Metode Verifikasi:** `POST /api/submissions/` dengan payload `{"challenge": 716, "flag": "academy{l1n3ar_f33dback_sh1ft_r3g}"}` pada REST API CyLab Security Academy. Respons server: `HTTP 201 Created` dengan `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Integritas Penanganan Entropi Kunci:** Jangan pernah memotong (*truncate*) material kunci acak menjadi sub-panjang yang tidak memadai. Modul LKS menuntut penggunaan fungsi derivasi kunci standar (HKDF / PBKDF2 sesuai NIST SP 800-132).
- **Kelemahan LFSR Polos:** LFSR linear tanpa fungsi pengacak non-linear tidak boleh digunakan secara langsung sebagai cipher aliran (*stream cipher*).
- **Validasi Minimum Keyspace:** Protokol keamanan data harus menjamin ruang pencarian minimal $2^{128}$ atau $2^{256}$ bit untuk mengeliminasi risiko serangan brute-force.
