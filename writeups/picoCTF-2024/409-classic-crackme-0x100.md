# Writeup: Classic Crackme 0x100 (Challenge ID: 409)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / ELF Binary Reversal & Keystream Inversion
- **Difficulty:** Medium
- **Author:** Nandan Desai
- **Event:** picoCTF 2024
- **Points:** 300
- **Flag:** `academy{s0lv3_angry_symb0ls_08254898}`

---

## Problem Statement & Scope
Tantangan menyajikan sebuah berkas eksekusi biner Linux ELF 64-bit berjudul `crackme100` serta sebuah instance kontainer on-demand yang menjalankan layanan socket TCP verifikasi password. Peserta diminta membalik logika verifikasi sandi pada biner lokal untuk menemukan kata sandi yang valid, kemudian mengirimkan kata sandi tersebut ke server kompetisi guna memperoleh flag resmi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Analisis Struktur Fungsi `main()` & Konstruksi Ciphertext:**
   Biner tidak di-strip (`not stripped`) dan memuat simbol debug DWARF. Pada prolog fungsi `main()`, program menyusun string ciphertext sasaran sepanjang 50 byte pada frame stack lokal `[rbp-0x80]`:
   `dhomvajazmxwwmiiuhpqctvzzsxxixjkmuproxkhdruonhytwl`
   Input pengguna diterima melalui `scanf("%50s", &input)` ke dalam buffer stack `[rbp-0x40]`.

2. **Mekanisme Transformasi Deterministik (Popcount Caesar Shift):**
   Program menjalankan loop luar sebanyak 3 putaran (`round = 0, 1, 2`). Pada setiap putaran, setiap karakter input pada indeks `i` ($0 \le i < 50$) dimodifikasi menggunakan algoritma bit-twiddling penghitung Hamming weight (popcount) dari nilai `i % 255`:
   - Operasi bit-twiddling:
     ```c
     int count = (i % 255);
     count = (count & 0x55) + ((count >> 1) & 0x55);
     count = (count & 0x33) + ((count >> 2) & 0x33);
     count = (count & 0x0f) + ((count >> 4) & 0x0f);
     ```
   - Operasi pergeseran karakter alfabet:
     ```c
     input[i] = 'a' + ((input[i] - 'a' + count) % 26);
     ```
   Setelah 3 putaran selesai, pergeseran total bersifat linear dan kumulatif:
   $$\text{shift}_{\text{total}}(i) = (3 \times \text{popcount}(i \pmod{255})) \pmod{26}$$

3. **Inversi Aljabar Deterministik:**
   Karena pergeseran merupakan pemetaan bijektif modulo 26 pada himpunan karakter `[a-z]`, karakter asli kata sandi pada setiap posisi dapat dipulihkan secara instan melalui operasi pengurangan modulo:
   $$\text{password}[i] = \text{chr}\Big(\text{ord}('a') + \big((\text{ord}(\text{target}[i]) - \text{ord}('a') - 3 \times \text{popcount}(i \pmod{255})) \pmod{26}\big)\Big)$$
   Pemulihan karakter menghasilkan kata sandi plaintext:
   `delgsudrwgrnqdzwrbjhwkmntjolzlxvjojiiobvxilcevmeqc`

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Disassembly & Analisis Statis Biner:**
   ```bash
   objdump -d -M intel crackme100
   ```
   Mengidentifikasi konstanta popcount (`0x55`, `0x33`, `0x0f`), modulo 26 (`imul 0x1a`), serta 3 iterasi loop luar.

2. **Ekstraksi String Ciphertext Sasaran:**
   Merekonsiliasi data dari instruksi `movabs` pada prolog stack:
   ```text
   dhomvajazmxwwmiiuhpqctvzzsxxixjkmuproxkhdruonhytwl
   ```

3. **Penyusunan Skrip Inversi Python:**
   ```python
   target = "dhomvajazmxwwmiiuhpqctvzzsxxixjkmuproxkhdruonhytwl"
   pwd = []
   for i, ch in enumerate(target):
       shift = (3 * bin(i % 255).count("1")) % 26
       pwd.append(chr(ord("a") + (ord(ch) - ord("a") - shift) % 26))
   password = "".join(pwd)
   ```

4. **Validasi Biner Lokal:**
   ```bash
   ./crackme100 <<< "delgsudrwgrnqdzwrbjhwkmntjolzlxvjojiiobvxilcevmeqc"
   ```
   Output: `SUCCESS! Here is your flag: academy{sample_flag}`

5. **Interaksi Remote Server via Socket TCP:**
   Menghubungkan ke layanan remote `nc xebec.cylabacademy.net 10569` dan mengirimkan password yang telah dipulihkan. Server membalas dengan flag asli:
   `academy{s0lv3_angry_symb0ls_08254898}`

---

## Flag & Verifikasi
- **Password Terpulihkan:** `delgsudrwgrnqdzwrbjhwkmntjolzlxvjojiiobvxilcevmeqc`
- **Flag Resmi:** `academy{s0lv3_angry_symb0ls_08254898}`
- **Verifikasi Platform:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 409, "flag": "academy{s0lv3_angry_symb0ls_08254898}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Algoritma Bit-Twiddling:** Peserta LKS Cyber Security bidang Reverse Engineering harus terlatih mengenali pola pergeseran bit klasik seperti penghitungan bobot Hamming (popcount) tanpa bergantung sepenuhnya pada dekompiler tingkat tinggi (Ghidra/IDA).
2. **Kelemahan Obfuscation Deterministik:** Menggunakan transformasi substitusi sederhana berbasis indeks posisi (Caesar cipher terotasi) tidak memberikan perlindungan kriptografis karena operasi matematika tersebut sepenuhnya dapat dibalik (invertible) secara aljabar.
3. **Penerapan Kriptografi Kuat (Mitigasi):** Untuk verifikasi kata sandi, aplikasi wajib menggunakan fungsi hash satu arah yang tahan terhadap serangan brute-force dan pra-komputasi (seperti Argon2id, bcrypt, atau PBKDF2 dengan salt kriptografis unik), bukan sekadar transformasi reversibel di sisi klien.
