# Writeup: ARMssembly 3 (Challenge ID: 106)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / ARMv8-A Assembly Tracing
- **Difficulty:** Hard
- **Author:** Dylan McGuire
- **Event:** picoCTF 2021
- **Points:** 130
- **Flag:** `academy{00000024}`

---

## Problem Statement & Scope
Diberikan berkas kode assembly ARMv8-A 64-bit bernama `chall_3.S`. Aplikasi memproses satu parameter numerik baris perintah melalui pemanggilan fungsi `atoi()`, meneruskannya ke fungsi `func1()`, lalu mencetak hasil perhitungan register ke konsol standar. Peserta diminta menghitung nilai kembalian saat program dipanggil dengan argumen numerik $a = 605030239$. Flag diserahkan dalam format heksadesimal 32-bit huruf kecil dengan panjang 8 digit (`academy{XXXXXXXX}`).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Analisis Algoritma Ekstraksi Bit (Population Count / Hamming Weight):**
   - Fungsi `func1` mengimplementasikan algoritma penghitungan bit aktif (set bits) pada suatu integer.
   - Operasi `and w0, w0, 1` mengisolasi bit paling tidak signifikan (Least Significant Bit / LSB).
   - Operasi `lsr w0, w0, 1` (Logical Shift Right) menggeser seluruh representasi bit ke arah kanan sebesar 1 posisi, memindahkan bit berikutnya ke posisi LSB dan mengisi bit tertinggi dengan nilai nol.

2. **Dekomposisi Fungsi Modular ARM64:**
   - Ketika LSB bernilai `1` (`beq .L3` tidak diambil), fungsi memanggil `func2(acc)`:
     ```assembly
     func2:
       sub sp, sp, #16
       str w0, [sp, 12]
       ldr w0, [sp, 12]
       add w0, w0, 3
       add sp, sp, 16
       ret
     ```
   - Fungsi pembantu `func2` secara deterministik menambahkan konstanta `3` ke nilai akumulator saat ini.
   - Dengan demikian, relasi aljabar antara nilai input dan nilai akhir akumulator dinyatakan sebagai:
     $$\text{Hasil Akhir} = \text{popcount}(a) \times 3$$
     di mana $\text{popcount}(a)$ adalah jumlah digit biner bernilai `1` pada representasi input.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Alur Kontrol Assembly (`func1`):**
   - Simpan argumen input: `str w0, [sp, 28]`
   - Inisialisasi akumulator: `str wzr, [sp, 44]` ($\text{acc} = 0$)
   - Lompat ke pemeriksaan kondisi awal: `b .L2`
   - Blok `.L2`: Evaluasi apakah input masih bernilai bukan nol (`cmp w0, 0` diikuti `bne .L4`). Jika `w0 == 0`, perulangan selesai.
   - Blok `.L4`: Uji LSB dengan `and w0, w0, 1`. Jika bernilai nol, lewati pemanggilan fungsi ke `.L3`. Jika bernilai satu, panggil `func2` untuk menambahkan `3` pada akumulator.
   - Blok `.L3`: Geser bit input ke kanan sejauh 1 bit (`lsr w0, w0, 1`) dan simpan kembali ke memori.

2. **Dekomposisi Biner Input:**
   - Nilai desimal: $a = 605030239$
   - Konversi ke format heksadesimal 32-bit:
     $$605030239 = \text{0x2410075f}$$
   - Konversi ke bit-stream biner 32-bit:
     $$\text{0x2410075f} = 0010\ 0100\ 0001\ 0000\ 0000\ 0111\ 0101\ 1111_2$$
   - Hitung jumlah bit `1` (popcount):
     - `0010` $\implies$ 1
     - `0100` $\implies$ 1
     - `0001` $\implies$ 1
     - `0000` $\implies$ 0
     - `0000` $\implies$ 0
     - `0111` $\implies$ 3
     - `0101` $\implies$ 2
     - `1111` $\implies$ 4
     - Total bit 1 = $1 + 1 + 1 + 0 + 0 + 3 + 2 + 4 = 12$ bit aktif.

3. **Perhitungan Hasil Akhir:**
   $$\text{accumulator} = 12 \times 3 = 36 \text{ (desimal)}$$
   - Konversi nilai 36 ke format heksadesimal 32-bit 8-digit bertipe lowercase:
     $$36 = 2 \times 16 + 4 = \text{0x00000024} \implies \text{00000024}$$
   - Format flag: `academy{00000024}`.

4. **Validasi Solver Reproduktif:**
   ```bash
   python3 scripts/solve_106_armssembly_3.py
   ```
   Output: `Flag: academy{00000024}`

---

## Flag & Verifikasi
- **Flag:** `academy{00000024}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons status HTTP 201 Created dengan hasil validasi `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Takeaway LKS:** Pengenalan pola operasi bitwise tingkat rendah (seperti bit masking dan logical shift right) untuk mengekstraksi metrik numerik seperti Hamming weight merupakan keterampilan penting dalam analisis kriptografi ringan, algoritma hashing, dan pendeteksian pola encoding biner pada materi Reverse Engineering LKS Cyber Security.
- **Mitigasi Defensif:** Dalam implementasi komputasi performa tinggi pada ARM64, loop ekstraksi bit manual harus digantikan oleh instruksi intrinsik perangkat keras khusus yang berjalan dalam satu siklus clock (seperti instruksi ARMv8 NEON `cnt` atau fungsi bawaan compiler `__builtin_popcount()`), yang tidak rentan terhadap serangan side-channel berbasis waktu (timing attacks) yang bergantung pada jumlah bit aktif.
