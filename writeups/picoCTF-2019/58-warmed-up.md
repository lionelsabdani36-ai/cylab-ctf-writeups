# Writeup: Warmed Up (Challenge ID: 58)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Radix Conversion & Hexadecimal Representation
- **Difficulty:** Easy (diff=1)
- **Author:** Sanjay C/Danny Tunitis
- **Event:** picoCTF 2019
- **Points:** 50
- **Flag:** `academy{61}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman konversi nilai numerik berbobot dari representasi basis 16 (heksadesimal) ke basis 10 (desimal):
> *"What is 0x3D (base 16) in decimal (base 10)? Submit your answer in our flag format. For example, if your answer was '22', you would submit 'academy{22}' as the flag."*

Tujuan modul bimbingan teknis ini adalah memperkuat pemahaman fundamental representasi heksadesimal yang digunakan secara universal dalam pemetaan alamat memori virtual, opcode mesin, hexdump analisis artefak, dan inspeksi protokol jaringan.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Sistem Bilangan Posisi Berbasis 16 (Hexadecimal Radix):**
   - Sistem heksadesimal memanfaatkan 16 simbol unik: `0-9` merepresentasikan nilai $0$ hingga $9$, dan `A-F` (atau `a-f`) merepresentasikan nilai kuantitatif $10$ hingga $15$ ($A=10, B=11, C=12, D=13, E=14, F=15$).
   - Formulasi konversi polinomial posisional berbasis $b=16$:
     $$N_{10} = \sum_{i=0}^{n-1} d_i \cdot 16^i$$
   - Untuk nilai $0\text{x}3D$:
     - Digit LSB ($i=0$): $D_{16} = 13_{10} \implies 13 \cdot 16^0 = 13 \cdot 1 = 13$
     - Digit MSB ($i=1$): $3_{16} = 3_{10} \implies 3 \cdot 16^1 = 3 \cdot 16 = 48$
     - Akumulasi total: $48 + 13 = 61_{10}$

2. **Relevansi Arsitektur Sistem & Standar NIST SP 800-115:**
   - Evaluasi keamanan sistem dan inspeksi biner menuntut pembacaan cepat representasi bita memori. Satu bita (byte / 8-bit) direpresentasikan tepat oleh 2 digit heksadesimal (nibble tinggi dan nibble rendah, rentang `0x00` hingga `0xFF` atau 0 hingga 255).
   - Kesalahan interpretasi basis bilangan (CWE-704 / Incorrect Type Conversion) sering menjadi akar cacat logika dalam validasi panjang paket buffer, otentikasi token, dan perhitungan ukuran chunk alokasi memori.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Konversi Manual Terstruktur:**
   - Ekstrak digit nibble: `3` dan `D`.
   - Ubah simbol `D` menjadi nilai kuantitas: $13$.
   - Hitung berbobot: $(3 \times 16) + 13 = 48 + 13 = 61$.

2. **Verifikasi via Lingkungan CLI Linux:**
   Menggunakan ekspresi shell Bash atau `bc`:
   ```bash
   echo "$((16#3D))"
   ```
   Keluaran:
   ```text
   61
   ```
   Atau via utilitas `printf`:
   ```bash
   printf "%d\n" 0x3D
   ```
   Keluaran:
   ```text
   61
   ```

3. **Verifikasi via Python One-Liner:**
   ```bash
   python3 -c 'print(int("0x3D", 16))'
   ```
   Keluaran:
   ```text
   61
   ```

4. **Pembentukan Format Token Kompetisi:**
   Format token sesuai instruksi adalah `academy{61}`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{61}`
- **Verifikasi API Platform:** Validasi token melalui `POST /api/submissions/` menghasilkan respons sukses:
  ```json
  {"user": 1072359, "challenge": 58, "flag": "academy{61}", "correct": true, "historical": false}
  ```
  Status kode HTTP 201 Created mengonfirmasi keabsahan token.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Peserta lomba LKS bidang Cyber Security wajib terbiasa memproses nilai heksadesimal tanpa alat bantu eksternal. Kasus konkret meliputi identifikasi magic bytes berkas (`0x50 0x4B` untuk ZIP, `0x7F 0x45 0x4C 0x46` untuk ELF), perhitungan offset instruksi asm (`EIP/RIP relative addressing`), dan deobfuski string XOR heksadesimal.
- **Mitigasi Defensif (Secure Coding):** Pengembang perangkat lunak wajib menetapkan basis parsing numerik secara tegas dan eksplisit pada fungsi konversi string-ke-integer (misal: `Integer.parseInt(val, 16)` di Java atau `strtol(nptr, &endptr, 16)` di C/C++). Hindari asumsi deteksi otomatis basis yang tidak aman (`base = 0`) pada input yang berasal dari pengguna luar guna menangkal eksploitasi ambiguitas format parsing.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_58_warmed_up.py`.
