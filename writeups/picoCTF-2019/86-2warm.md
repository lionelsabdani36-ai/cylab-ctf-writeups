# Writeup: 2warm (Challenge ID: 86)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Radix Conversion & Binary Representation
- **Difficulty:** Easy (diff=1)
- **Author:** Sanjay Bastola
- **Event:** picoCTF 2019
- **Points:** 50
- **Flag:** `academy{101010}`

---

## Problem Statement & Scope

Tantangan menanyakan konversi nilai numerik basis 10 (desimal) ke dalam representasi basis 2 (biner):
> *"Can you convert the number 42 (base 10) to binary (base 2)? Submit your answer in our competition's flag format. For example, if your answer was '11111', you would submit 'academy{11111}' as the flag."*

Tujuan modul pembelajaran ini adalah menguji penguasaan konsep dasar representasi data tingkat rendah (*low-level data representation*), arsitektur bilangan komputasi digital, dan kemampuan transformasi radix tanpa ketergantungan kalkulator grafis atau antarmuka GUI.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Prinsip Positional Number Systems & Representasi Radix:**
   - Dalam sistem bilangan posisional berbobot (*weighted positional number system*), sebuah bilangan bulat tak bertanda dinyatakan sebagai:
     $$N = \sum_{i=0}^{k-1} d_i \cdot b^i$$
     di mana $b$ adalah basis/radix ($b=10$ untuk desimal, $b=2$ untuk biner), dan $d_i$ adalah digit pada posisi $i$.
   - Untuk mengonversi desimal $42_{10}$ ke biner $b=2$:
     - $42 / 2 = 21$, sisa $0$ (LSB - Least Significant Bit)
     - $21 / 2 = 10$, sisa $1$
     - $10 / 2 = 5$, sisa $0$
     - $5 / 2 = 2$, sisa $1$
     - $2 / 2 = 1$, sisa $0$
     - $1 / 2 = 0$, sisa $1$ (MSB - Most Significant Bit)
   - Mengumpulkan sisa pembagian dari MSB ke LSB menghasilkan untaian bit: `101010`.
   - Melalui dekomposisi pangkat dua: $42 = 32 + 8 + 2 = 2^5 + 2^3 + 2^1 \rightarrow 101010_2$.

2. **Relevansi Keamanan Sistem (NIST SP 800-115 & Reversing/Exploitation):**
   - Dalam analisis biner, *reverse engineering*, dan analisis lalu lintas jaringan, representasi bitwise merupakan representasi atomik memori (masking, bit-shifting, bitwise XOR/AND/OR).
   - Pemahaman yang akurat mengenai bitwise encoding mencegah galat parsing dan kekeliruan interpretasi tipe data (*type confusion* atau *integer truncation*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Konversi Manual atau Menggunakan Utilitas Bash:**
   Konversi nilai desimal $42$ dapat diverifikasi langsung melalui shell ekspresi Bash atau `bc`:
   ```bash
   echo "obase=2; 42" | bc
   ```
   Keluaran:
   ```text
   101010
   ```

2. **Evaluasi Cepat via Python CLI:**
   ```bash
   python3 -c "print(bin(42)[2:])"
   ```
   Keluaran:
   ```text
   101010
   ```

3. **Formulasi Token Flag:**
   Sesuai instruksi soal, masukkan untaian bit ke dalam format wrapper `academy{...}`:
   ```text
   academy{101010}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{101010}`
- **Verifikasi API:** Validasi token pada endpoint `POST /api/submissions/` mengembalikan `{"correct": true, "challenge": 86}` (Status HTTP 201 Created).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Fondasi Biner untuk LKS Cyber Security:** Peserta kompetisi LKS wajib mampu mengonversi antar-radix (biner, oktal, desimal, heksadesimal) secara instan dalam memori kepala maupun skrip singkat. Kemampuan ini vital saat membaca hexdump (`xxd`, `hexdump -C`), menyusun format string payload, dan mengurai instruksi opcode mesin x86/ARM.
- **Standar Penanganan Konversi Input (Defensive):** Pada implementasi aplikasi defensif (CWE-704), parser bilangan wajib memvalidasi basis string numerik secara eksplisit (misalnya `strtol(str, NULL, 10)` atau `strtol(str, NULL, 0)`) guna mencegah celah ambigu di mana input berawalan `0` diinterpretasikan sebagai oktal atau `0x` sebagai heksadesimal yang berpotensi memicu manipulasi logika otentikasi.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_86_2warm.py`.
