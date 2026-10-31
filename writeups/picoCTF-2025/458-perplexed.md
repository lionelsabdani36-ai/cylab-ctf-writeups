# 458 - perplexed (Reverse Engineering, picoCTF 2025, Medium)

## Challenge Metadata
- ID: 458 | Event: picoCTF 2025 | Author: LT 'syreal' Jones
- Category: Reverse Engineering | Difficulty: Medium (2)
- Flag: `academy{0n3_bi7_4t_a_7im3}`

## Problem Statement & Scope
Tantangan menyediakan berkas biner eksekusi Linux x86-64 `perplexed`. Program meminta pengguna memasukkan kata sandi rahasia melalui baris perintah (*stdin*). Apabila masukan cocok, program mencetak pesan `Correct!! :D`, dan sebaliknya mencetak kegagalan. Peserta diminta membedah logika validasi biner untuk merekonstruksi string flag asli.

## Teori & Akar Kerentanan (Root Cause)
1. **Analisis Fungsi Pengujian Biner (Static Disassembly & ABI Call):**
   Biner tidak mengalami *stripping* simbol (`not stripped`). Fungsi `main` membaca masukan menggunakan `fgets(buf, 0x100, stdin)`, yang secara bawaan menyertakan karakter newline (`\n`), kemudian meneruskan pointer buffer ke fungsi `check`.
2. **Restriksi Panjang Masukan (Boundary Check):**
   Fungsi `check` memanggil `strlen(input)` dan membandingkannya dengan nilai heksadesimal `0x1b` (27 desimal). Karena panjang string mencakup 26 karakter token flag dan 1 karakter newline (`\n`), batas validasi mengharuskan masukan tepat 27 bita.
3. **Penyusunan Buffer Tumpukan Tumpang Tindih (Overlapping Stack Buffer Initialization):**
   Pada frame fungsi `check`, array referensi sepanjang 23 bita disusun melalui tiga instruksi pemuatan qword 64-bit langsung:
   - `[rbp-0x50] = 0x61fb7cbb4c0e8fc3` (indeks 0..7)
   - `[rbp-0x48] = 0xd269df5b5afc9db9` (indeks 8..15)
   - `[rbp-0x41] = 0xf467edf4ed1bfed2` (indeks 15..22, tumpang tindih 1 bita pada indeks 15)
4. **Transformasi Bita 7-bit ASCII Packing (Bitstream Transposition):**
   Loop validasi mengekstrak bita dari array referensi secara sekuensial (MSB ke LSB, $1 \ll (7 - \text{ref\_bit})$). Pada buffer masukan, program melakukan pergeseran bita dengan melewati bita tertinggi ($0$-th MSB, karena karakter ASCII berada pada rentang $[0, 127]$ dengan MSB selalu $0$), dan mencocokkan bita ke-1 hingga ke-7 ($1 \ll (7 - \text{input\_bit})$). Dengan demikian, setiap karakter ASCII masukan direkonstruksi dari tepat 7 bita aliran referensi:
   $$26 \times 7 = 182 \text{ bita} \le 23 \times 8 = 184 \text{ bita}$$

## Rekonstruksi Eksploitasi Step-by-Step
1. Ekstraksi urutan bita referensi pada memori tumpukan:
   - Bita 0..7: `c3 8f 0e 4c bb 7c fb 61`
   - Bita 8..15: `b9 9d fc 5a 5b df 69 d2`
   - Bita 15..22: `d2 fe 1b ed f4 ed 67 f4` (menimpa indeks 15 dengan `d2`)
2. Konversi 23 bita referensi ke dalam aliran bita tunggal (*bitstream*) sepanjang 184 bita (MSB ke LSB).
3. Pemetaan kembali (*un-packing*) 7 bita per karakter ASCII:
   - Inisialisasi `curr_char = 0`.
   - Untuk setiap bita ke-$i \in [1..7]$, set `curr_char |= bit << (7 - i)`.
   - Setelah 7 bita diproses, simpan `curr_char` sebagai karakter ASCII yang terpulihkan.
4. Hasil dekode karakter menghasilkan:
   `academy{0n3_bi7_4t_a_7im3}` (26 karakter).
5. Pengujian lokal biner:
   ```bash
   echo "academy{0n3_bi7_4t_a_7im3}" | ./perplexed
   # Output: Enter the password: Correct!! :D
   ```
6. Verifikasi via API CyLab:
   `POST /api/submissions/` dengan payload `{"challenge": 458, "flag": "academy{0n3_bi7_4t_a_7im3}"}` menghasilkan respons `{"correct": true, "historical": false}`.

## Flag & Verifikasi
- `academy{0n3_bi7_4t_a_7im3}` (Status: Verified `correct: true`, `historical: false`).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Obfuskasi Tingkat Bit & Aliran Data (Bit-Level Packing Defenses):** Teknik pengemasan bita non-standar (7-bit packing) sering digunakan malware untuk menyembunyikan payload konfigurasi C2 dari deteksi string statis (`strings` / YARA rule dasar).
- **In-Memory Hardening & Control Flow Integrity:** Pengembang aplikasi komersial harus mengaburkan logika validasi kunci menggunakan kriptografi asimetris atau HMAC terotentikasi daripada operasi perbandingan bita langsung yang rentan terhadap pembedahan statis (*reverse engineering*).
