# Writeup: Investigative Reversing 2 (Challenge ID: 13)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Bitmap LSB Steganography & Binary Reversing
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 350
- **Author:** Danny Tunitis
- **Flag:** `academy{n3xt_0n30000000000000000000000000825f5086}`

---

## Problem Statement & Scope
Tantangan `Investigative Reversing 2` merupakan modul forensik steganografi tingkat lanjut. Peserta diberikan satu biner ELF 64-bit `mystery` dan sebuah berkas gambar raster tidak terkompresi `encoded.bmp`. Program biner memvalidasi bahwa masukan token harus tepat sepanjang 50 karakter, kemudian menyembunyikan bit-bit data rahasia ke dalam struktur piksel gambar bitmap mulai dari offset byte tertentu.

Ruang lingkup pengujian mencakup analisis struktur berkas BMP (Windows Bitmap Header / DIB Header), dekompilasi rutin penyisipan LSB (*Least Significant Bit steganography*), pemulihan aliran bit Little-Endian, inversi pergeseran nilai byte, serta kepatuhan metodologi forensik **NIST SP 800-115 Section 4.3**.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Steganografi Least Significant Bit (LSB) pada Media Citra Digital:**
   - Format BMP menyimpan nilai warna piksel secara mentah (*uncompressed raw byte arrays*). Memodifikasi bit paling tidak signifikan (bit ke-0 / LSB) dari komponen warna hanya mengubah intensitas warna sebesar $\pm 1/256$, sebuah fluktuasi imperseptibel yang mustahil dideteksi oleh mata telanjang manusia.
   - Program biner mengarahkan kursor penulisan melompati 2000 byte pertama (`fseek` / loop `fread` 2000 byte header dan piksel awal), lalu menuliskan muatan data tersembunyi pada blok piksel berikutnya.

2. **Kelemahan Penyamaran Berbasis Pergeseran Aritmatika Statis (CWE-312 / CWE-327):**
   - Sebelum disisipkan bit per bit ke dalam LSB piksel, biner menerapkan operasi pengurangan statis `flag[j] - 5`.
   - Fungsi `codedChar(int bit_idx, byte char_val, byte carrier_byte)` mengekstrak bit ke-`bit_idx` (urutan LSB-first) menggunakan `(char_val >> bit_idx) & 1` dan menimpanya ke bit-0 dari `carrier_byte` melalui formula `(carrier_byte & 0xFE) | bit`.
   - Karena panjang flag diketahui persis 50 byte ($50 \times 8 = 400$ bit) dan transformasi bersifat bijektif linear tanpa kunci dinamis, seluruh isi data dapat direkonstruksi dengan membaca bit LSB dari offset 2000 s.d. 2399 lalu menambahkan kembali offset nilai $+5$.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Dekompilasi Biner ELF (Ghidra):**
   - Dekompilasi rutin `main` mengungkap logika penulisan:
     ```c
     fread(flag, 50, 1, flag_file);
     if (flag_bytes_read < 1) {
         puts("flag is not 50 chars");
         exit(0);
     }
     for (j = 0; j < 50; j++) {
         for (k = 0; k < 8; k++) {
             uVar3 = codedChar(k, flag[j] - 5, b);
             fputc((int)(char)uVar3, encoded_file);
             fread(&b, 1, 1, original_file);
         }
     }
     ```
   - Implementasi `codedChar`:
     ```c
     ulong codedChar(int param_1, byte param_2, byte param_3) {
         byte shifted = param_2;
         if (param_1 != 0) {
             shifted = (byte)((int)(char)param_2 >> ((byte)param_1 & 0x1f));
         }
         return (ulong)(param_3 & 0xfe | shifted & 1);
     }
     ```

2. **Inspeksi Nilai Heksadesimal Carrier pada `encoded.bmp`:**
   - Mengamati rentang byte di sekitar offset 2000 (0x7D0):
     ```bash
     xxd -g 1 -s 1980 -l 64 encoded.bmp
     ```
   - Ditemukan bahwa sebelum offset 2000 byte bernilai konstan `0xe8` (`0b11101000`). Mulai dari offset 2000, nilai byte bervariasi antara `0xe8` dan `0xe9` (`0b11101001`), menandakan modulasi bit LSB sepanjang 400 byte hingga offset 2400 (0x960).

3. **Demultiplexing Aliran Bit & Rekonstruksi Byte Karakter:**
   - Untuk setiap blok 8 byte $k \in [0..7]$ pada indeks karakter $j \in [0..49]$:
     - Ambil $bit_k = byte[2000 + 8j + k] \ \& \ 1$.
     - Rekonstruksi nilai tergeser: $val = \sum_{k=0}^{7} (bit_k \ll k)$.
     - Pulihkan karakter asli: $flag[j] = val + 5$.
   - Rekonstruksi 50 karakter menghasilkan string token:
     `academy{n3xt_0n30000000000000000000000000825f5086}`

4. **Validasi Skrip Otomasi Mandiri:**
   - Menjalankan solver reproduktif:
     ```bash
     python3 scripts/solve_13_investigative_reversing_2.py
     ```
   - Skrip memverifikasi keberhasilan ekstraksi dan integritas 50 karakter token.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{n3xt_0n30000000000000000000000000825f5086}`
- **Komunitas Standar (CTF Format):** `CTF{n3xt_0n30000000000000000000000000825f5086}`
- **Status Verifikasi:** Terverifikasi 100% pada ekstraksi LSB bitstream dan pemulihan little-endian byte array.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Steganalisis Citra LSB (Chi-Square & Sample Pair Analysis):**
   Penyisipan bit LSB secara berurutan (*sequential LSB insertion*) menciptakan ketidakseimbangan statistik pada pasangan nilai warna genap dan ganjil (PoVs - *Pairs of Values*). Gunakan analisis statistik Chi-square atau perangkat steganalisis (seperti `zsteg` atau `stegdetect`) untuk mendeteksi distorsi distribusi bit pada gambar bitmap.
2. **Standardisasi Pemrosesan Gambar (Sanitization Pipelines):**
   Seluruh aset grafis yang melewati gerbang keamanan organisasi harus dinormalisasi melalui kuantisasi ulang atau konversi format terkompresi (lossy JPEG/WebP) untuk melenyapkan payload LSB yang disusupkan pada piksel gambar.
3. **Pilar Kompetensi LKS Cyber Security:**
   Penguasaan manipulasi bitwise (`>>`, `&`, `|`, `<<`), struktur heksadesimal file header, dan teknik ekstraksi bit mentah (*raw bitstream parsing*) adalah kemampuan inti dalam kompetisi bidang Forensik Digital.
