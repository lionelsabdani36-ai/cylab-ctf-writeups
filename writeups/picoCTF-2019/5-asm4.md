# Writeup: asm4 (Challenge ID: 5)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / x86 Assembly Tracing
- **Difficulty:** Hard
- **Author:** Sanjay C
- **Event:** picoCTF 2019
- **Points:** 400
- **Flag:** `0x1df`

---

## Problem Statement & Scope
Diberikan berkas assembly x86 `test.S`. Peserta diminta menganalisis fungsi `asm4` saat menerima input string pointer `asm4("academy_0a649")`. Nilai kembalian register `eax` wajib diserahkan dalam representasi heksadesimal berawalan `0x`.

---

## Teori & Analisis Arsitektur x86 IA-32
1. **Loop Penentuan Panjang String (Strlen Emulation):**
   - Inisialisasi `[ebp-0x10] = 0x236` (akumulator basis) dan `[ebp-0xc] = 0` (penghitung indeks panjang string).
   - Loop pertama memeriksa byte `BYTE PTR [eax + edx]` hingga menemukan byte null (`\0`), sehingga `[ebp-0xc]` menyimpan panjang string $N = 13$ untuk string input `"academy_0a649"`.

2. **Loop Transformasi & Sifat Telescoping Deret:**
   - Loop kedua mengiterasikan indeks $i$ (`[ebp-0x8]`) dari $1$ sampai $N - 2$ ($1 \le i \le 11$).
   - Pada setiap iterasi $i$, biner mengeksekusi:
     $$\Delta_1 = S[i] - S[i-1]$$
     $$\Delta_2 = S[i+1] - S[i]$$
     $$\text{accumulator} \mathrel{+}= \Delta_1 + \Delta_2$$
   - Secara aljabar, suku tengah saling meniadakan (telescoping series):
     $$\Delta_1 + \Delta_2 = (S[i] - S[i-1]) + (S[i+1] - S[i]) = S[i+1] - S[i-1]$$
   - Akumulasi total seluruh iterasi dari $i=1$ hingga $i=11$:
     $$\sum_{i=1}^{11} (S[i+1] - S[i-1]) = (S[12] + S[11]) - (S[1] + S[0])$$

---

## Rekonstruksi & Verifikasi Eksekusi
1. **Perhitungan Analitis Manual:**
   - String $S = \text{"academy\_0a649"}$ dengan panjang $N = 13$:
     - $S[0] = \text{'a'} = 97$
     - $S[1] = \text{'c'} = 99 \implies S[0] + S[1] = 196$
     - $S[11] = \text{'4'} = 52$
     - $S[12] = \text{'9'} = 57 \implies S[11] + S[12] = 109$
   - Selisih total: $109 - 196 = -87$.
   - Akumulator akhir: $0x236 (566) - 87 = 479 = \text{0x1df}$.

2. **Eksekusi Biner Native 32-bit:**
   Program assembly mandiri dirakit menggunakan `as --32` dan dihubungkan via `ld -m elf_i386`, lalu dieksekusi langsung pada kernel Linux:
   Output: `0x000001df` $\implies$ `0x1df`.

3. **Eksekusi Script Solver Reproduktif:**
   ```bash
   python3 scripts/solve_5_asm4.py
   ```
   Output: `Flag: 0x1df`

---

## Flag & Verifikasi
- **Flag:** `0x1df`
- **Verifikasi:** POST `/api/submissions/` merespons `{"correct": true}` (HTTP Status 201 Created).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Takeaway LKS:** Pengenalan pola dekompilasi loop pemrosesan string dan simplifikasi aljabar atas deret pergeseran karakter sangat krusial dalam reverse engineering untuk mengidentifikasi algoritma hashing atau checksum kustom tanpa harus melakukan debugging manual instruksi demi instruksi.
- **Mitigasi Defensif:** Validasi batas indeks array/pointer string pada level bahasa tingkat rendah (C/C++) harus selalu menggunakan tipe data `size_t` dengan pemeriksaan underflow/overflow eksplisit saat mengakses offset relatif seperti $i-1$ dan $i+1$.
