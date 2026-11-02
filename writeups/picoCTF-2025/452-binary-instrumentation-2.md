# Writeup: Binary Instrumentation 2 (Challenge ID: 452)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Windows Binary Instrumentation & LZMA Unpacking
- **Difficulty:** Medium
- **Author:** Venax
- **Event:** picoCTF 2025
- **Points:** 300
- **Flag:** `academy{fr1da_f0r_b1n_in5trum3nt4tion!_b21aef39}`

---

## Problem Statement & Scope
Tantangan menyajikan sebuah biner Windows PE32+ (x86-64) berjudul `bininst2.exe` yang terkemas dalam arsip berpasword ZIP (`academy`). Deskripsi persoalan menguraikan skenario di mana sebuah aplikasi Windows dimaksudkan untuk membuat file baru dan menuliskan flag ke dalamnya, namun operasi penulisan tersebut gagal pada runtime. Peserta ditantang untuk mencegat (intercept) panggilan fungsi penulisan file Windows API guna menganalisis penyebab kegagalan dan mendapatkan flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyelubungan Kode Melalui Seksi Khusus (`.ATOM` / LZMA Stream):**
   Sama seperti varian Binary Instrumentation 1, berkas eksekusi luar (`bininst2.exe`) bertindak sebagai self-extracting stub loader. Header PE32+ mendefinisikan seksi khusus bernama `.ATOM` pada physical raw offset berkas `0x6000` dengan ukuran virtual `0x6ade1` byte. Seksi ini diawali oleh magic bytes stream LZMA (`0x5D 0x00 0x00 0x10 0x00`) dengan kamus alokasi memori 1 MB. Dekompresi stream LZMA secara statis langsung mengekstraksi executable PE32+ internal sebesar 2.331.678 byte.

2. **Kegagalan Runtime I/O Windows API (`CreateFileW` / `WriteFile`):**
   Pada biner internal yang telah didekompresi, alur eksekusi memanggil fungsi Win32 I/O:
   - `CreateFileW` untuk membuka handle file.
   - `WriteFile` untuk menuliskan buffer data flag ke handle file tersebut.
   Namun, pengembang mengonfigurasi parameter nama berkas target menggunakan placeholder mentah (`<Insert path here>`). Karena string tersebut mengandung karakter terlarang dalam sistem berkas Windows (`<` dan `>`) serta tidak mengarah pada jalur absolut/relatif yang valid, panggilan `CreateFileW` menghasilkan `INVALID_HANDLE_VALUE` (Error 123: `ERROR_INVALID_NAME`), sehingga panggilan `WriteFile` berikutnya gagal tanpa memproduksi berkas apapun di disk.

3. **Intended Path (Dynamic Binary Instrumentation via Frida):**
   Secara desain dinamis, peserta diarahkan untuk mengaitkan (hooking) fungsi `WriteFile` sebelum eksekusi atau mencegat parameter `lpBuffer` pada panggilan I/O menggunakan Frida:
   ```javascript
   Interceptor.attach(Module.getExportByName('kernel32.dll', 'WriteFile'), {
       onEnter: function (args) {
           var buf = args[1];
           var len = args[2].toInt32();
           console.log('Intercepted Buffer: ' + Memory.readUtf8String(buf, len));
       }
   });
   ```

4. **Vektor Analisis Statis Defensif Tanpa Runtime Windows:**
   Karena kompresi LZMA bersifat deterministik dan tidak disertai enkripsi kunci simetris tambahan, buffer data yang akan dikirimkan ke `WriteFile` sudah tersimpan dalam segmen data biner internal. Tepat setelah string placeholder `<Insert path here>`, tersimpan representasi Base64:
   `YWNhZGVteXtmcjFkYV9mMHJfYjFuX2luNXRydW0zbnQ0dGlvbiFfYjIxYWVmMzl9`
   yang dapat didekode secara langsung menjadi flag kompetisi tanpa memerlukan emulator Wine atau mesin virtual Windows.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Arsip dan Pemeriksaan Header PE:**
   ```bash
   unzip -P academy bininst2.zip
   objdump -h bininst2.exe
   ```
   Ditemukan seksi `.ATOM` pada offset `0x6000`.

2. **Dekompresi Muatan Internal Menggunakan Python `lzma`:**
   ```python
   import lzma
   with open("bininst2.exe", "rb") as f:
       raw = f.read()
   decompressed = lzma.decompress(raw[0x6000:])
   ```

3. **Ekstraksi String Base64 Buffer Tulis:**
   ```python
   import base64, re
   m = re.search(rb"YWNhZGVte[A-Za-z0-9+/=]+", decompressed)
   flag = base64.b64decode(m.group(0)).decode()
   print(flag)
   ```

4. **Eksekusi Solver Standalone:**
   Menjalankan skrip reproduktif `scripts/solve_452_binary_instrumentation_2.py`:
   ```bash
   python3 scripts/solve_452_binary_instrumentation_2.py
   ```
   Menghasilkan flag resmi:
   `academy{fr1da_f0r_b1n_in5trum3nt4tion!_b21aef39}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{fr1da_f0r_b1n_in5trum3nt4tion!_b21aef39}`
- **Verifikasi Platform:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 452, "flag": "academy{fr1da_f0r_b1n_in5trum3nt4tion!_b21aef39}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Packer Non-Standar:** Peserta LKS bidang Cyber Security dituntut mampu mengenali tanda-tanda kompresi/penyelubungan kode (packing) melalui pemeriksaan anomali rasio ukuran seksi virtual vs raw data serta header magic bytes (misal LZMA `0x5d00001000`).
2. **Validasi Input Jalur File (Hardening):** Pada pengembangan aplikasi yang berinteraksi dengan API sistem berkas, parameter path wajib divalidasi terhadap daftar karakter terlarang sistem operasi dan memastikan penanganan return value API (memeriksa `INVALID_HANDLE_VALUE` dan memanggil `GetLastError()`).
3. **Penyimpanan Data Rahasia di Memori (Secret Hygiene):** String sensitif (seperti kredensial atau token) dilarang disimpan dalam bentuk Base64 statis dalam file biner. Gunakan teknik proteksi memori, enkripsi berbasis DPAPI / TPM, atau penurunan hak akses runtime sebelum memproses data sensitif.
