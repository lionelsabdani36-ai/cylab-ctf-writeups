# Writeup: function overwrite (Challenge ID: 272)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Negative Indexing & Function Pointer Overwrite (CWE-129 / CWE-822)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2022
- **Points:** 400
- **Author:** Neel Bhavsar
- **Flag:** `academy{0v3rwrit1ng_P01nt3rs_2ba33ab3}`

---

## Problem Statement & Scope
Tantangan `function overwrite` menyajikan program biner ELF 32-bit (`vuln`) dan kode sumber C pendukung (`vuln.c`). Program meminta pengguna memasukkan sebuah string narasi ("story"), menghitung skor cerita berdasarkan penjumlahan nilai ASCII karakter, dan kemudian meminta dua buah bilangan bulat: `num1` (indeks array) dan `num2` (nilai penambah). Program menggunakan *function pointer* global untuk memverifikasi skor sebelum memutuskan apakah flag akan dicetak. Peserta diarahkan untuk menganalisis batas validasi indeks dan tata letak memori biner guna mengalihkan pointer fungsi verifikasi ke rutin pemenang (*winning function*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Improper Validation of Array Index (Signed Integer OOB, CWE-129):**
   Program mendeklarasikan struktur data pada memori global:
   ```c
   void (*check)(char*, size_t) = hard_checker;
   int fun[10] = {0};
   ```
   Operasi penulisan ke dalam array diatur melalui logika:
   ```c
   if (num1 < 10) {
       fun[num1] += num2;
   }
   ```
   Variabel `num1` bertipe *signed integer* (`int`). Pengecekan `num1 < 10` hanya memvalidasi batas atas (*upper bound*), tetapi sama sekali mengabaikan batas bawah (*lower bound*, `num1 >= 0`). Oleh karena itu, nilai indeks negatif apa pun (misal `-1`, `-16`) akan lolos validasi logika dan menghasilkan akses memori *out-of-bounds* (OOB) mundur di ruang memori sebelum `fun`.
2. **Korupsi Function Pointer (CWE-822):**
   Dalam biner 32-bit yang dikompilasi tanpa PIE (*Position Independent Executable*), pointer fungsi `check` dialokasikan secara statis di alamat memori tetap sebelum array `fun` (`check` pada `0x0804c034` dan `fun` pada `0x0804c060`). Dengan selisih jarak $-44$ byte, indeks offset relatif elemen integer 32-bit adalah `num1 = -44 / 4 = -11`. Ekspresi `fun[-11] += num2` memungkinkan penyerang menambahkan nilai sembarang langsung ke alamat yang disimpan dalam `check` (*Arbitrary Value Addition / Write-What-Where*).
3. **Mekanisme Penebusan Checker:**
   - `hard_checker`: Memeriksa apakah skor cerita bernilai `13371337`. Karena panjang cerita dibatasi pada buffer 64 byte (skor maksimum $64 \times 127 = 8128$), kondisi ini mustahil dipenuhi secara matematis.
   - `easy_checker`: Memeriksa apakah skor cerita bernilai `1337`. Kondisi ini dapat dengan mudah dipenuhi melalui rekayasa kombinasi karakter ASCII.
   Dengan menghitung selisih alamat $\Delta = \text{easy\_checker} - \text{hard\_checker} = 0x08049238 - 0x0804936e = -310$, menambahkan $\Delta$ ke `fun[-11]` mengubah nilai `check` menjadi alamat `easy_checker`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Perhitungan Selisih Alamat Simbol Biner:**
   Analisis simbol biner melalui `objdump -t vuln` atau GDB mengungkapkan:
   - Alamat `hard_checker`: `0x0804936e`
   - Alamat `easy_checker`: `0x08049238`
   - Nilai penambah: $\Delta = 0x08049238 - 0x0804936e = -310$.
   - Alamat `check`: `0x0804c034`, Alamat `fun`: `0x0804c060` $\rightarrow$ Indeks `num1 = (0x0804c034 - 0x0804c060) / 4 = -11`.
2. **Penyusunan String Cerita (Skor ASCII Tepat 1337):**
   Diperlukan string yang menghasilkan total nilai ASCII tepat `1337`:
   - Karakter tilde `~` memiliki nilai ASCII `126`.
   - $10 \times 126 = 1260$.
   - Sisa yang dibutuhkan: $1337 - 1260 = 77$. Nilai ASCII `77` bersesuaian dengan karakter huruf kapital `'M'`.
   - String cerita yang digunakan: `"~~~~~~~~~~M"`.
3. **Pemberian Input Interaktif ke Program:**
   - Input 1 (Story): `~~~~~~~~~~M`
   - Input 2 (Array Index & Value): `-11 -310`
4. **Verifikasi Alur Eksekusi & Penerimaan Flag:**
   Rutin `check(story, len)` memanggil `easy_checker("~~~~~~~~~~M", 11)`. Kondisi `score == 1337` bernilai benar, membuka `flag.txt`, dan mencetak output:
   `academy{0v3rwrit1ng_P01nt3rs_2ba33ab3}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{0v3rwrit1ng_P01nt3rs_2ba33ab3}`
- **Native PicoCTF Flag:** `picoCTF{0v3rwrit1ng_P01nt3rs_2ba33ab3}`
- **Verifikasi API Platform:** Penyerahan token melalui endpoint REST API `POST /api/submissions/` menghasilkan status **HTTP 201 Created**:
  ```json
  {
    "user": 1072359,
    "challenge": 272,
    "flag": "academy{0v3rwrit1ng_P01nt3rs_2ba33ab3}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Validasi Batas Indeks Lengkap (Dual-Bound Validation, NIST SP 800-115 §5.3):**
   Selalu gunakan tipe data tanpa tanda (*unsigned integer* seperti `size_t` atau `unsigned int`) untuk indeks array, dan validasi kedua batas secara eksplisit:
   ```c
   size_t idx;
   if (scanf("%zu %d", &idx, &num2) == 2) {
       if (idx < 10) {
           fun[idx] += num2;
       }
   }
   ```
2. **Proteksi Writable Function Pointer (Full RELRO & W^X / DEP):**
   Jangan menempatkan pointer fungsi di segmen data yang memiliki izin tulis (`.data` / `.bss`). Jika fungsi harus dikonfigurasi secara dinamis, pastikan proteksi *Full RELRO* aktif (`-Wl,-z,relro,-z,now`) sehingga tabel fungsi dijadikan *read-only* setelah inisialisasi awal.
3. **Penerapan Control Flow Integrity (CFI):**
   Gunakan kompilasi dengan fitur integritas alur kontrol seperti Clang Forward-Edge CFI (`-fsanitize=cfi`) atau Intel Control-flow Enforcement Technology (CET) guna memvalidasi bahwa target pemanggilan pointer fungsi tidak pernah melenceng ke fungsi yang tidak sah.
