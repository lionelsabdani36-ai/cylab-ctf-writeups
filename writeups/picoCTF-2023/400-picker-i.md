# Writeup: Picker I (Challenge ID: 400)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Dynamic Eval Code Execution & Hex Output Reconstruction
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2023 / picoGym Exclusive
- **Points:** 100
- **Flag:** `academy{4_d14m0nd_1n_7h3_r0ugh_ce4b5d5b}`

---

## Problem Statement & Scope

Diberikan sebuah skrip Python bernama `picker-I.py` yang dijalankan sebagai layanan soket interaktif via TCP. Program meminta input string dari pengguna dengan petunjuk `Try entering "getRandomNumber" without the double quotes...`. Skrip kemudian menyambungkan input pengguna dengan tanda kurung buka-tutup `()` lalu mengevaluasi string tersebut menggunakan fungsi bawaan `eval()`. Peserta ditugaskan untuk menganalisis kode sumber, mengidentifikasi fungsi internal yang dapat mengekspos token bendera, mengeksekusinya dari jarak jauh, dan mendekode output heksadesimal yang dihasilkan.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Injeksi Kode Melalui `eval()` (CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code):**
   - Dalam kode sumber `picker-I.py`:
     ```python
     while(True):
       try:
         print('Try entering "getRandomNumber" without the double quotes...')
         user_input = input('==> ')
         eval(user_input + '()')
       except Exception as e:
         print(e)
         break
     ```
   - Penggunaan `eval()` untuk mengimplementasikan *dynamic dispatch* fungsi tanpa daftar putih (*allowlist*) memungkinkan penyerang mengeksekusi sembarang *callable* dalam lingkup variabel global maupun lokal.
2. **Fungsi Tersembunyi `win()`:**
   - Pemeriksaan terhadap kode sumber skrip menunjukkan deklarasi fungsi berikut:
     ```python
     def win():
       flag = open('flag.txt', 'r').read()
       flag = flag.strip()
       str_flag = ''
       for c in flag:
         str_flag += str(hex(ord(c))) + ' '
       print(str_flag)
     ```
   - Fungsi `win()` membaca berkas `flag.txt`, mengonversi setiap karakter menjadi nilai representasi heksadesimal berbasis ASCII, lalu mencetaknya ke konsol.
3. **Rekonstruksi Data Heksadesimal ke ASCII:**
   - Deretan heksadesimal yang dipisahkan oleh spasi (misalnya `0x70 0x69 0x63 0x6f...`) merepresentasikan nilai numerik kode karakter ASCII:
     - `0x70` $\rightarrow$ `112` $\rightarrow$ `'p'`
     - `0x69` $\rightarrow$ `105` $\rightarrow$ `'i'`
     - `0x63` $\rightarrow$ `99` $\rightarrow$ `'c'`
     - `0x6f` $\rightarrow$ `111` $\rightarrow$ `'o'`
   - Memetakan setiap token melalui `chr(int(token, 16))` merekonstruksi string flag lengkap secara deterministik.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Analisis alur eksekusi `picker-I.py` dan catat ketiadaan filter masukan pengguna.
2. Hubungkan ke layanan remote TCP menggunakan netcat atau skrip socket:
   ```bash
   nc saturn.picoctf.net <port>
   ```
3. Saat prompt `==> ` muncul, kirimkan nama fungsi `win`:
   ```text
   ==> win
   ```
4. Layanan mengeksekusi `eval("win()")` dan membalas dengan rentetan nilai byte heksadesimal:
   ```text
   0x70 0x69 0x63 0x6f 0x43 0x54 0x46 0x7b 0x34 0x5f 0x64 0x31 0x34 0x6d 0x30 0x6e 0x64 0x5f 0x31 0x6e 0x5f 0x37 0x68 0x33 0x5f 0x72 0x30 0x75 0x67 0x68 0x5f 0x63 0x65 0x34 0x62 0x35 0x64 0x35 0x62 0x7d
   ```
5. Dekode deretan heksadesimal menggunakan Python satu baris (*one-liner*):
   ```python
   raw = "0x70 0x69 0x63 0x6f 0x43 0x54 0x46 0x7b 0x34 0x5f 0x64 0x31 0x34 0x6d 0x30 0x6e 0x64 0x5f 0x31 0x6e 0x5f 0x37 0x68 0x33 0x5f 0x72 0x30 0x75 0x67 0x68 0x5f 0x63 0x65 0x34 0x62 0x35 0x64 0x35 0x62 0x7d"
   flag = "".join(chr(int(x, 16)) for x in raw.split())
   print(flag)
   # Output: picoCTF{4_d14m0nd_1n_7h3_r0ugh_ce4b5d5b}
   ```
6. Sesuaikan format pembungkus komunitas platform CyLab: `academy{4_d14m0nd_1n_7h3_r0ugh_ce4b5d5b}`.
7. Jalankan skrip verifikasi otomatis `scripts/solve_400_picker_i.py` untuk memastikan kepatuhan logika pengujian.

---

## Flag & Verifikasi

- **Flag:** `academy{4_d14m0nd_1n_7h3_r0ugh_ce4b5d5b}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 400, "flag": "academy{4_d14m0nd_1n_7h3_r0ugh_ce4b5d5b}", "correct": true}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Identifikasi pola *insecure function dispatching* dalam audit kode sumber Python.
  - Pemahaman mendalam tentang bahaya eksekusi dinamis string dan teknik serialisasi data tingkat rendah (ASCII/Hex decoding).
- **Mitigasi Defensif:**
  - **Hindari Fungsi `eval()` / `exec()`:** Jangan pernah menyalurkan input yang berasal dari pengguna luar ke evaluator dinamis interpreter bahasa pemrograman.
  - **Gunakan Dictionary Dispatch Table:**
    Ganti evaluasi dinamis dengan tabel asosiasi statis:
    ```python
    DISPATCHER = {
        'getRandomNumber': getRandomNumber,
        'exit': exit
    }
    func = DISPATCHER.get(user_input.strip())
    if func:
        func()
    else:
        print("Invalid command")
    ```
    Dengan pola ini, fungsi sensitif seperti `win()` tidak akan pernah dapat diakses atau dipanggil dari luar tanpa izin eksplisit.
