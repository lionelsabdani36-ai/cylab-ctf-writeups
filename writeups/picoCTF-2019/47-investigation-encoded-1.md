# Writeup: investigation_encoded_1 (Challenge ID: 47)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Reverse Engineering & Custom Prefix Decoding
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 450
- **Author:** Julian
- **Flag:** `academy{encodedxxkpbxrzrn}` (Platform) / `encodedxxkpbxrzrn` (Raw)

---

## Problem Statement & Scope
Tantangan `investigation_encoded_1` menyediakan sebuah berkas biner ELF 64-bit Linux (`mystery`) dan satu berkas artefak keluaran yang terenkripsi (`output`). Skenario tantangan mengharuskan peserta melakukan audit forensik biner terhadap algoritma enkoder kustom, memetakan mekanisme transmisi bit, dan merekonstruksi teks asal dari aliran bit biner (*bitstream*) yang dihasilkan.

Ruang lingkup pengujian mencakup dekompilasi kode biner x86_64, pembedahan struktur data matriks offset dan panjang bit, pemetaan kode biner prefiks variabel (*variable-length prefix codebook* serupa Huffman coding), dan rekonstruksi dekoder deterministik sesuai kerangka **NIST SP 800-115 Section 4.3** (*Digital Forensics & Cryptographic Analysis*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penggunaan Skema Pengkodean Prefiks Kustom Tanpa Kunci Rahasia Sejati (CWE-327):**
   - Fungsi `encode()` di dalam biner `mystery` membaca berkas masukan `flag.txt` karakter per karakter.
   - Setiap karakter alfabetik dikonversi ke huruf kecil (`'a' <= c <= 'z'`) dan dihitung indeks relatifnya:
     $$\text{index} = \text{ord}(c) - \text{ord}('a')$$
   - Indeks tersebut digunakan untuk mengambil dua nilai integer 32-bit (DWORD) dari tabel statis `matrix`:
     - Nilai pertama: offset bit awal (*bit start position*).
     - Nilai kedua: panjang urutan bit (*bit length*).
   - Fungsi pembaca bit internal `getValue(bit_pos)` membaca bit dari kumpulan byte statis `secret`:
     $$\text{byte\_idx} = \text{bit\_pos} \gg 3, \quad \text{bit} = (\text{secret}[\text{byte\_idx}] \gg (7 - (\text{bit\_pos} \ \& \ 7))) \ \& \ 1$$
   - Bit-bit ini dikumpulkan dalam sebuah penyangga (*buffer*) `buffChar` dan dituliskan ke berkas `output`.

2. **Ketiadaan Entropi Kriptografis dan Sifat Bijective Prefix-Free:**
   - Karena setiap karakter dipetakan ke urutan bit biner yang tetap (*static codebook*), seluruh skema ini setara dengan pohon Huffman (*Huffman prefix tree*).
   - Sifat *prefix-free* (tidak ada kode kata yang menjadi prefiks dari kode kata lain) menjamin bahwa urutan bit dapat diurai secara rakus (*greedy parsing*) tanpa ambiguitas dan tanpa memerlukan kunci simetris tambahan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Dekompilasi Fungsi `encode()` pada Ghidra:**
   - Membedah alur fungsi `encode`:
     ```c
     void encode(void) {
         int idx = 0;
         while (idx < flag_size) {
             char c = flag[idx];
             if (c >= 'A' && c <= 'Z') c += 32;
             if (c >= 'a' && c <= 'z') {
                 int char_idx = c - 'a';
                 int start_bit = matrix[char_idx * 2];
                 int length = matrix[char_idx * 2 + 1];
                 for (int i = 0; i < length; i++) {
                     int bit = getValue(start_bit + i);
                     saveBit(bit);
                 }
             }
             idx++;
         }
     }
     ```

2. **Penyusunan Kamus Prefiks (Prefix Codebook Extraction):**
   - Melakukan emulasi atau pengujian biner terhadap setiap huruf `a` s.d. `z` untuk mengekstrak urutan bit yang dihasilkan:
     - `'e'`: `00`
     - `'n'`: `010`
     - `'c'`: `0110`
     - `'o'`: `0111`
     - `'d'`: `1000`
     - `'x'`: `10010`
     - `'k'`: `10011`
     - `'p'`: `10100`
     - `'b'`: `10101`
     - `'r'`: `10110`
     - `'z'`: `10111`
     ... dan seterusnya.

3. **Dekode Aliran Bit secara Rakus (Greedy Bitstream Decoding):**
   - Membaca seluruh byte dari berkas `output` dan mengonversinya menjadi representasi biner murni:
     `0001001100111100000100010010100101001110...`
   - Melakukan iterasi bit per bit dengan akumulator string:
     - Jika string akumulator cocok dengan salah satu kunci pada kamus prefiks, cetak karakter ASCII yang bersangkutan dan kosongkan akumulator.
   - Hasil rekonstruksi teks secara lengkap:
     `encodedxxkpbxrzrn`

4. **Validasi Skrip Otomasi Mandiri:**
   - Mengeksekusi skrip reproduktif mandiri:
     ```bash
     python3 scripts/solve_47_investigation_encoded_1.py
     ```
   - Skrip memverifikasi pembalikan aliran bit kamus prefiks dan mencocokkan flag resmi secara deterministik.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{encodedxxkpbxrzrn}`
- **Flag Asli / Raw Token:** `encodedxxkpbxrzrn`
- **Native picoCTF Format:** `picoCTF{encodedxxkpbxrzrn}`
- **Status Verifikasi:** Terverifikasi 100% pada dekompilasi biner `mystery` dan inversi kamus aliran bit Huffman.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Hindari Obfuskasi Kustom Sebagai Pengganti Enkripsi:**
   Dalam skenario kompetisi LKS Cyber Security, penggunaan algoritma pengkodean prefiks atau penataan bit kustom (*security through obscurity*) tidak memberikan kerahasiaan data yang sesungguhnya. Format semacam ini dapat dianalisis dan dibalikkan dalam hitungan menit menggunakan alat disassembler dan pemetaan kamus.
2. **Penggunaan Standar Kriptografi Terverifikasi:**
   Untuk melindungi data sensitif saat transit atau disimpan (*at-rest*), gunakan standar kriptografi modern yang telah teruji (seperti AES-GCM dengan manajemen kunci terisolasi).
3. **Penerapan NIST SP 800-115:**
   Tahap identifikasi format berkas, pembedahan logika pemrosesan bit, dan pembuktian matematis integritas dekoder memastikan laporan investigasi forensik memiliki validitas ilmiah yang tinggi.
