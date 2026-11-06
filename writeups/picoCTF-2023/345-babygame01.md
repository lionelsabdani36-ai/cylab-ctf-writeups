# Writeup: babygame01 (Challenge ID: 345)

- Platform: CyLab Security Academy (picoCTF)
- Category: Binary Exploitation / Out-of-Bounds Tile Grid Indexing & Stack Variable Overwrite
- Difficulty: Medium (diff=2)
- Author: LT 'syreal' Jones
- Event: picoCTF 2023
- Points: 100
- Flag: `academy{gamer_m0d3_enabled_9ad09239}`

---

## Problem Statement & Scope

Tantangan menyajikan simulasi permainan navigasi berbasis teks ASCII pada platform Linux 32-bit:
> *"Get the flag and reach the exit.*
> *Welcome to BabyGame! Navigate around the map and see what you can find!*
> *The game is available to download here. There is no source available, so you'll have to figure your way around the map.*
> 
> *`nc xebec.cylabacademy.net <port>`"*

Peserta diberikan biner ELF 32-bit x86 bernama `game` tanpa kode sumber. Biner memuat peta matriks berukuran 30x90 karakter di mana pemain (disimbolkan karakter `@`) harus menjelajah hingga mencapai koordinat keluar. Namun, mencapai pintu keluar secara normal tanpa kondisi prasyarat tertentu tidak memunculkan flag. Target audit adalah merekayasa balik (*reverse engineering*) struktur frame tumpukan biner, menemukan ketiadaan validasi batas koordinat pemain, dan memanipulasi variabel status flag pada stack.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Tata Letak Variabel Lokal pada Frame Tumpukan 32-bit (Stack Frame Layout):**
   - Disassembly subrutin `main` memperlihatkan alokasi ruang stack lokal sebesar `0xaa0` bita:
     - Koordinat Baris Pemain (`player.row`): Alamat `[ebp - 0xaa4]` (4 bita, diinisialisasi nilai 4).
     - Koordinat Kolom Pemain (`player.col`): Alamat `[ebp - 0xaa0]` (4 bita, diinisialisasi nilai 4).
     - Status Boolean Pembawa Bendera (`has_flag`): Alamat `[ebp - 0xa9c]` (1 bita, diinisialisasi nilai 0).
     - Buffer Matriks Peta (`map[30][90]`): Alamat `[ebp - 0xa98]` (2700 bita array karakter berturut-turut).
   - Perhatikan posisi relatif variabel `has_flag`:
     - Lokasi awal peta: `ebp - 0xa98`.
     - Lokasi `has_flag`: `ebp - 0xa9c` = `(ebp - 0xa98) - 4`.
     - Variabel `has_flag` terletak tepat 4 bita di bawah (*lower address*) batas dasar array peta.

2. **Ketiadaan Pengecekan Batas Array (CWE-129 & CWE-787):**
   - Di dalam subrutin `move_player()`, perhitungan alamat sel tujuan dihitung secara aritmatika tanpa validasi batas minimum:
     ```text
     80495a3:  imul   eax,esi,0x5a    ; eax = row * 90
     80495a6:  add    eax,ecx         ; eax = (row * 90) + map_base
     80495a8:  add    eax,edx         ; eax = map_base + (row * 90) + col
     80495aa:  mov    BYTE PTR [eax],0x2e  ; tulis titik '.' pada posisi lama
     ...
     8049618:  imul   eax,esi,0x5a
     804961b:  add    eax,ebx
     804961d:  add    eax,ecx
     804961f:  mov    BYTE PTR [eax],dl    ; tulis karakter pemain pada posisi baru
     ```
   - Input `'w'`, `'s'`, `'a'`, dan `'d'` masing-masing melakukan decrement/increment terhadap `row` dan `col`.
   - Tidak terdapat instruksi kondisional yang memblokir nilai koordinat negatif (`row < 0` atau `col < 0`).
   - Apabila kita memposisikan pemain pada koordinat `row = 0` dan `col = -4`, formula alamat menghasilkan:
     `map_base + (0 * 90) + (-4) = map_base - 4 = [ebp - 0xa9c]`.
   - Pada saat posisi tersebut diisi karakter pemain (`@`, nilai ASCII 0x40), byte pada `[ebp - 0xa9c]` (`has_flag`) tertimpa dari 0 menjadi 0x40 (non-zero / bernilai `true`).

3. **Verifikasi Kemenangan dan Backdoor Perintah 'p':**
   - Dalam loop `main`, kondisi keluar diperiksa:
     ```text
     8049816:  mov    eax,DWORD PTR [ebp-0xaa4] ; row
     804981c:  cmp    eax,0x1d                 ; 29 desimal
     804981f:  jne    80497d1
     8049821:  mov    eax,DWORD PTR [ebp-0xaa0] ; col
     8049827:  cmp    eax,0x59                 ; 89 desimal
     804982a:  jne    80497d1
     804982c:  ...
     804983e:  movzx  eax,BYTE PTR [ebp-0xa9c] ; baca has_flag
     8049845:  test   al,al                    ; apakah bernilai non-zero?
     8049847:  je     8049874
     804985b:  call   8049223 <win>            ; jalankan win()
     ```
   - Subrutin `move_player()` juga menyediakan handler tersembunyi untuk karakter `'p'` (`cmp al, 0x70`), yang memanggil subrutin pembantu pengembang `solve_round()`. Subrutin ini memindahkan posisi pemain secara otomatis hingga tepat mencapai `row = 29` dan `col = 89`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Kalkulasi Offset Gerakan:**
   - Pemain mulai pada koordinat awal `row = 4`, `col = 4`.
   - Untuk mencapai koordinat `(0, -4)`:
     - Tekan `'w'` sebanyak 4 kali: `row` bergeser dari 4 menjadi 0.
     - Tekan `'a'` sebanyak 8 kali: `col` bergeser dari 4 menuju 0, lalu masuk ke indeks negatif hingga -4.
   - Penulisan karakter tile pemain menimpa `has_flag` di alamat `ebp - 0xa9c`.

2. **Pemicuan Penyelesaian Otomatis:**
   - Setelah variabel flag aktif, kirim karakter `'p'`.
   - Fungsi `solve_round()` berjalan, melakukan auto-navigation ke koordinat `(29, 89)`.
   - Loop `main` mendeteksi pemain telah berada di pintu keluar dan `has_flag` bernilai non-zero.
   - Program memanggil fungsi `win()`, yang membuka `flag.txt` dan mencetak isinya.

3. **Rangkaian Payload Eksploitasi Soket:**
   - Rangkai seluruh instruksi ke dalam satu stream TCP:
     ```python
     payload = b"w" * 4 + b"a" * 8 + b"p\n"
     s.sendall(payload)
     ```
   - Program mencetak respon:
     ```text
     You win!
     flage
     academy{gamer_m0d3_enabled_9ad09239}
     ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{gamer_m0d3_enabled_9ad09239}`
- **Flag Komunitas:** `CTF{gamer_m0d3_enabled_9ad09239}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 345, "flag": "academy{gamer_m0d3_enabled_9ad09239}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Bahaya Akses Indeks Array Tanpa Batas Bawah (Underflow / Negative Indexing):**
   - Dalam kompetensi LKS Cyber Security bidang Binary Analysis, pemrogram sering kali hanya memvalidasi batas atas indeks array (misalnya `col < 90`), namun lupa memvalidasi batas bawah (`col >= 0`) atau menggunakan tipe data `signed int` untuk indeks array. Indeks negatif memungkinkan penulisan ke alamat memori sebelum buffer, menimpa variabel lokal lain pada tumpukan.
2. **Mitigasi Rekayasa Perangkat Lunak:**
   - **Gunakan Tipe Data Unsigned:** Definisikan koordinat array menggunakan `size_t` atau `unsigned int`. Dengan tipe data unsigned, pengurangan di bawah nol akan memicu integer underflow menjadi angka raksasa (`UINT_MAX`), yang akan langsung tertangkap oleh validasi batas atas.
   - **Pemeriksaan Batas Eksplisit (Bounds Checking):**
     ```c
     if (new_row < 0 || new_row >= MAP_ROWS || new_col < 0 || new_col >= MAP_COLS) {
         // Tolak pergerakan di luar batas grid
         return;
     }
     ```
   - **Pemisahan Memori Status Sensitif:** Jangan letakkan variabel penentu otorisasi atau status keamanan di dekat buffer data yang dapat dimodifikasi oleh input pengguna.
   - **Hapus Debug Routine Sebelum Rilis:** Hapus seluruh backdoor pengembang seperti pintasan `'p'` yang memanggil `solve_round()` pada versi produksi aplikasi.
