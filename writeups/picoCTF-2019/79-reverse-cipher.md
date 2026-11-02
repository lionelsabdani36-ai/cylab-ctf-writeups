# 79 - reverse_cipher (Reverse Engineering, picoCTF 2019, Medium)

## Challenge Metadata
- ID: 79 | Event: picoCTF 2019 | Author: Danny
- Category: Reverse Engineering | Difficulty: Medium (3) | Points: 300
- Flag: `academy{r3v3rs356673ca1}`

## Problem Statement & Scope
Tantangan mendistribusikan berkas biner ELF x86_64 `rev` dan berkas terenkripsi `rev_this` berisi string `academy{w1{1wq83;4<1h_6}`. Peserta diminta membalik alur enkripsi pada biner untuk mengungkap flag asli yang dimasukkan ke dalam program sebelum proses transformasi.

## Teori & Akar Kerentanan (Root Cause)
1. **Reversible Symmetric Character Transposition (CWE-327 / Use of a Broken or Risky Cryptographic Algorithm):**
   Program membaca 24 byte dari berkas `flag.txt` ke dalam buffer stack `[rbp - 0x50]`. Alur transformasi karakter dieksekusi dalam tiga fase deterministik:
   - **Fase 1 (Prefix Header, Indeks 0..7):**
     Karakter indeks 0 sampai 7 (`academy{`) ditulis ke berkas output secara langsung tanpa modifikasi:
     ```c
     for (int i = 0; i <= 7; i++) {
         fputc(flag[i], out);
     }
     ```
   - **Fase 2 (Payload Body, Indeks 8..22):**
     Karakter indeks 8 hingga 22 dimodifikasi berdasarkan paritas indeks (`i & 1`):
     ```c
     for (int i = 8; i <= 22; i++) {
         if ((i & 1) == 0) {  // Genap (Even)
             fputc(flag[i] + 5, out);
         } else {             // Ganjil (Odd)
             fputc(flag[i] - 2, out);
         }
     }
     ```
   - **Fase 3 (Suffix Terminator, Indeks 23):**
     Karakter penutup indeks 23 (`}`) ditulis langsung ke berkas output tanpa modifikasi:
     ```c
     fputc(flag[23], out);
     ```
2. **Ketiadaan Kompleksitas Kriptografis (Linear Additive Shift):**
   Karena operasi enkripsi hanya merupakan pergeseran aditif modular konstan (+5 untuk genap, -2 untuk ganjil) tanpa ketergantungan antar-karakter (non-avalanche effect) atau kunci rahasia eksternal, fungsi inversi dapat dibentuk secara langsung dengan membalik tanda operasi matematika.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Logika Biner:**
   Melakukan disassembling fungsi `main()` dengan `objdump -d -M intel rev`. Menganalisis instruksi loop:
   - Loop pertama membandingkan counter loop terhadap `0x7` (`cmp DWORD PTR [rbp-0x8], 0x7`).
   - Loop kedua membandingkan counter loop terhadap `0x16` (22 desimal) (`cmp DWORD PTR [rbp-0xc], 0x16`).
   - Instruksi uji paritas: `and eax, 0x1` diikuti `test eax, eax`. Jalur tidak sama dengan 0 (`jne`) mengeksekusi `sub eax, 0x2`, sedangkan jalur genap mengeksekusi `add eax, 0x5`.
2. **Perumusan Algoritma Dekripsi (Inversi Matematis):**
   Untuk setiap indeks `i` dari 8 sampai 22 pada string ciphertext:
   $$\text{flag}[i] = \begin{cases} \text{cipher}[i] - 5 & \text{jika } i \equiv 0 \pmod 2 \\ \text{cipher}[i] + 2 & \text{jika } i \equiv 1 \pmod 2 \end{cases}$$
3. **Eksekusi Pemulihan Flag:**
   Memproses `academy{w1{1wq83;4<1h_6}`:
   - `w` (indeks 8, genap) $\to 119 - 5 = 114$ (`r`)
   - `1` (indeks 9, ganjil) $\to 49 + 2 = 51$ (`3`)
   - `{` (indeks 10, genap) $\to 123 - 5 = 118$ (`v`)
   - `1` (indeks 11, ganjil) $\to 49 + 2 = 51$ (`3`)
   - `w` (indeks 12, genap) $\to 119 - 5 = 114$ (`r`)
   - `q` (indeks 13, ganjil) $\to 113 + 2 = 115$ (`s`)
   - `8` (indeks 14, genap) $\to 56 - 5 = 51$ (`3`)
   - `3` (indeks 15, ganjil) $\to 51 + 2 = 53$ (`5`)
   - `;` (indeks 16, genap) $\to 59 - 5 = 54$ (`6`)
   - `4` (indeks 17, ganjil) $\to 52 + 2 = 54$ (`6`)
   - `<` (indeks 18, genap) $\to 60 - 5 = 55$ (`7`)
   - `1` (indeks 19, ganjil) $\to 49 + 2 = 51$ (`3`)
   - `h` (indeks 20, genap) $\to 104 - 5 = 99$ (`c`)
   - `_` (indeks 21, ganjil) $\to 95 + 2 = 97$ (`a`)
   - `6` (indeks 22, genap) $\to 54 - 5 = 49$ (`1`)
   Hasil pemulihan lengkap: `academy{r3v3rs356673ca1}`.

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_79_reverse_cipher.py`:
```python
def decrypt(ciphertext: bytes) -> str:
    flag = list(ciphertext)
    for i in range(8, 23):
        if i % 2 == 0:
            flag[i] -= 5
        else:
            flag[i] += 2
    return bytes(flag).decode()

print(decrypt(b"academy{w1{1wq83;4<1h_6}"))
```

## Mitigasi & Kepatuhan Standar (NIST SP 800-115 / SP 800-53)
- **NIST SP 800-53 SC-13 (Cryptographic Protection):** Hindari perancangan skema kriptografi ad-hoc/custom bergesekan linier (Security through obscurity). Terapkan algoritma kriptografi terstandarisasi FIPS 140-3 (seperti AES-GCM atau ChaCha20-Poly1305) dengan manajemen kunci terisolasi (NIST SP 800-57).
- **NIST SP 800-115 Bab 4 (Target Identification and Analysis):** Selalu lakukan verifikasi aliran data pada komponen yang menyimpan informasi sensitif guna memastikan seluruh muatan terenkripsi dengan skema non-deterministik berotentikasi.

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)
- **David (Leader):** Menetapkan pipeline reverse engineering statis menggunakan objdump x86_64.
- **Charlie (Trend-hunter):** Mengidentifikasi kemiripan varian substitusi/transposisi modular dalam soal-soal kurikulum LKS Nasional.
- **Alex (Fullstack-dev) & Omnirush (Executor):** Menulis skrip ekstraksi logika dan inversi byte Python.
- **Julius (QA-engineer):** Memverifikasi integritas hasil dekripsi karakter per karakter dan mencocokkan flag ke API CyLab.
- **Athena (Security-engineer):** Melakukan audit kelemahan CWE-327 dan pemetaan kontrol NIST SP 800-53 SC-13.
- **Judith (Guru LKS):** Mengintegrasikan studi kasus ini ke modul bimbingan teknis logika analisis assembly dan inversi fungsi matematika untuk siswa LKS.
