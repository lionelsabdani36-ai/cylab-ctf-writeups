# Writeup: Picker III (Challenge ID: 402)

- Platform: CyLab Security Academy (picoCTF)
- Category: Reverse Engineering / Dynamic Variable Corruption & Function Table Tampering
- Difficulty: Medium (diff=2)
- Author: LT 'syreal' Jones
- Event: picoCTF 2023 / picoGym Exclusive
- Points: 100
- Flag: `academy{7h15_15_wh47_w3_g37_w17h_u53r5_1n_ch4rg3_3e57e558}`

---

## Problem Statement & Scope

Tantangan menyajikan iterasi lanjutan dari seri *Picker*, menargetkan mekanisme *dispatching* pemanggilan fungsi berbasis tabel pada interpreter Python:
> *"Can you figure out how this program works to get the flag?*
> 
> *`$ nc chatelaine.cylabacademy.net <port>`"*

Pengguna diberikan akses ke kode sumber `picker-III.py` dan sebuah service TCP interaktif. Pengembang berusaha memitigasi kerentanan eksekusi arbitrer dari *Picker I* dan *Picker II* dengan mengganti eksekusi input langsung dengan sebuah tabel fungsi statis (`func_table`). Pengguna hanya diizinkan memilih nomor entri (1 hingga 4) yang terdaftar di dalam tabel. Target evaluasi adalah membedah implementasi tabel tersebut, menemukan vektor modifikasi variabel runtime, dan memaksa program memanggil subrutin `win()`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Penyimpanan Tabel Fungsi dalam String Global:**
   - Berbeda dari struktur data kamus (*dictionary*) atau senarai (*list*), program mengemas entri fungsi ke dalam sebuah string biner/teks tunggal:
     ```python
     FUNC_TABLE_SIZE = 4
     FUNC_TABLE_ENTRY_SIZE = 32

     def reset_table():
         global func_table
         func_table = \
     '''\
     print_table                     \
     read_variable                   \
     write_variable                  \
     getRandomNumber                 \
     '''
     ```
   - Total panjang string adalah `4 * 32 = 128` karakter. Fungsi `get_func(n)` mengambil irisan karakter pada rentang `n * 32` hingga `(n + 1) * 32` dan memotong spasi pengisi untuk mendapatkan nama fungsi yang akan dieksekusi melalui `eval(func_name + '()')`.

2. **Validasi Modifikasi Variabel Global yang Longgar (CWE-94 & CWE-284):**
   - Subrutin `write_variable()` menyediakan fungsionalitas penulisan variabel:
     ```python
     def filter_var_name(var_name):
         r = re.search('^[a-zA-Z_][a-zA-Z_0-9]*$', var_name)
         return True if r else False

     def filter_value(value):
         if ';' in value or '(' in value or ')' in value:
             return False
         return True

     def write_variable():
         var_name = input('Please enter variable name to write: ')
         if filter_var_name(var_name):
             value = input('Please enter new value of variable: ')
             if filter_value(value):
                 exec('global ' + var_name + '; ' + var_name + ' = ' + value)
     ```
   - Nama variabel `func_table` sepenuhnya valid menurut regex `filter_var_name`.
   - Filter nilai `filter_value` hanya menolak karakter titik koma (`;`) serta tanda kurung buka dan tutup (`()`). Nilai berupa string literal Python yang diapit tanda petik ganda (`"..."`) lolos secara sempurna dari filter.
   - Panggilan `exec()` kemudian menimpa variabel global `func_table` dengan nilai string arbitrer yang dikirimkan oleh pengguna.

3. **Integritas Pemeriksaan Tabel (`check_table`):**
   - Fungsi `check_table()` hanya memvalidasi panjang total string:
     ```python
     def check_table():
         if len(func_table) != FUNC_TABLE_ENTRY_SIZE * FUNC_TABLE_SIZE:
             return False
         return True
     ```
   - Selama string pengganti memiliki panjang tepat 128 karakter, pemeriksaan integritas mengembalikan status valid (`True`).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Perancangan Payload String Tabel Fungsi:**
   - Subrutin target adalah `win()`, yang membaca berkas `flag.txt` dan mencetak karakternya dalam bentuk representasi heksadesimal `0x..`.
   - Panjang entri tabel adalah 32 karakter. Kata `'win'` terdiri dari 3 karakter, sehingga membutuhkan 29 karakter spasi (`'win' + ' ' * 29`).
   - Karena `check_table()` mengharuskan panjang tepat 128 karakter, kita menduplikasi entri tersebut sebanyak 4 kali:
     ```python
     entry = "win" + " " * 29
     new_table = entry * 4  # 32 * 4 = 128 karakter
     payload = f'"{new_table}"'
     ```

2. **Interaksi Jaringan Soket:**
   - Hubungkan ke host dan port layanan via soket TCP.
   - Kirim pilihan `'3'` untuk menjalankan subrutin `write_variable()`.
   - Masukkan nama variabel target: `func_table`.
   - Masukkan nilai pengganti yang diformat string: `f'"{new_table}"'`.
   - Kirim pilihan `'1'` untuk memicu `call_func(0)`.
   - Program memanggil `get_func(0)` yang menghasilkan nama subrutin `'win'`, kemudian mengeksekusi `eval('win()')`.

3. **Dekode Ekstraksi Heksadesimal:**
   - Layanan memancarkan keluaran berupa urutan byte heksadesimal ASCII:
     ```text
     0x61 0x63 0x61 0x64 0x65 0x6d 0x79 0x7b 0x37 0x68 ...
     ```
   - Konversi setiap token `0x..` menjadi representasi karakter ASCII (`chr(int(token, 16))`) menyusun flag lengkap.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{7h15_15_wh47_w3_g37_w17h_u53r5_1n_ch4rg3_3e57e558}`
- **Flag Komunitas:** `CTF{7h15_15_wh47_w3_g37_w17h_u53r5_1n_ch4rg3_3e57e558}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 402, "flag": "academy{7h15_15_wh47_w3_g37_w17h_u53r5_1n_ch4rg3_3e57e558}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Bahaya `exec()` dan `eval()` pada Variabel Status Aplikasi:**
   - Dalam kompetensi LKS Cyber Security bidang Web & Script Auditing, memberikan pengguna kendali untuk menulis variabel lingkungan atau state aplikasi secara langsung via `exec()` merupakan celah fatal. Meskipun fungsi eksekusi dibatasi tabel, integritas tabel itu sendiri bergantung pada status memori yang dapat dimanipulasi.
2. **Mitigasi Arsitektur Defensif:**
   - **Tipe Data Imutabel:** Gunakan struktur data tuple atau mapping kamus yang di-freeze (misalnya `MappingProxyType`) sehingga modifikasi runtime terhadap tabel fungsi dilemparkan sebagai exception.
   - **Kompilasi Daftar Putih Fungsi Dinamis:** Jangan gunakan string untuk memanggil subrutin. Petakan masukan integer langsung ke fungsi referensi asli:
     ```python
     DISPATCH_TABLE = {
         1: print_table,
         2: read_variable,
         3: write_variable,
         4: getRandomNumber
     }
     ```
   - **Eliminasi Penulisan Variabel Bebas:** Hapus penggunaan `exec('global ' + var_name + ...)` dan batasi operasi hanya pada whitelist variabel yang didefinisikan secara eksplisit.
