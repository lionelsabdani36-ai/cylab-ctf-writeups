# Writeup: ASCII Numbers (Challenge ID: 390)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Hexadecimal Character Encoding
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2023 / picoGym Exclusive
- **Points:** 100
- **Flag:** `academy{45c11_n0_qu35710n5_1ll_t311_y3_n0_l135_e96c8ca8}`

---

## Problem Statement & Scope

Diberikan sebuah string yang memuat urutan angka heksadesimal berawalan prefiks `0x` yang merepresentasikan nilai byte ASCII:
```text
0x61 0x63 0x61 0x64 0x65 0x6d 0x79 0x7b 0x34 0x35 0x63 0x31 0x31 0x5f 0x6e 0x30 0x5f 0x71 0x75 0x33 0x35 0x37 0x31 0x30 0x6e 0x35 0x5f 0x31 0x6c 0x6c 0x5f 0x74 0x33 0x31 0x31 0x5f 0x79 0x33 0x5f 0x6e 0x30 0x5f 0x6c 0x31 0x33 0x35 0x5f 0x65 0x39 0x36 0x63 0x38 0x63 0x61 0x38 0x7d
```

Tantangan menginstruksikan peserta untuk mengonversi deretan angka heksadesimal tersebut ke dalam karakter teks yang dapat dibaca manusia (*readable string*) untuk menemukan token bendera resmi format `academy{...}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Standar Pengkodean Karakter ASCII (ANSI X3.4-1968):**
   - Standar ASCII (*American Standard Code for Information Interchange*) mendefinisikan pemetaan numerik 7-bit (nilai 0 hingga 127) ke karakter kontrol dan karakter cetak.
   - Karakter huruf kecil alfabetik (`a`-`z`) berada pada rentang desimal 97 (`0x61`) hingga 122 (`0x7a`).
   - Karakter angka (`0`-`9`) berada pada rentang desimal 48 (`0x30`) hingga 57 (`0x39`).
   - Simbol pembuka kurung kurawal `{` bernilai `0x7b` dan penutup `}` bernilai `0x7d`. Garis bawah `_` bernilai `0x5f`.
2. **Representasi Hexadecimal Stream:**
   - Komputer dan protokol jaringan sering kali mentransmisikan data biner atau teks dalam format heksadesimal dua digit per byte guna menghindari ambiguitas karakter kontrol non-cetak.
   - String `0x61 0x63 0x61 0x64 0x65 0x6d 0x79 0x7b ...` secara langsung memetakan byte demi byte:
     - `0x61` -> 'a'
     - `0x63` -> 'c'
     - `0x61` -> 'a'
     - `0x64` -> 'd'
     - `0x65` -> 'e'
     - `0x6d` -> 'm'
     - `0x79` -> 'y'
     - `0x7b` -> '{'
   - Proses rekonstruksi hanya memerlukan konversi basis 16 ke titik kode karakter ASCII.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Pisahkan seluruh token heksadesimal berdasarkan spasi.
2. Konversi setiap token dari basis 16 menjadi nilai byte numerik menggunakan utilitas Linux atau interpreter:
   - Menggunakan pipeline shell:
     ```bash
     echo "0x61 0x63 0x61 0x64 0x65 0x6d 0x79 0x7b 0x34 0x35 0x63 0x31 0x31 0x5f 0x6e 0x30 0x5f 0x71 0x75 0x33 0x35 0x37 0x31 0x30 0x6e 0x35 0x5f 0x31 0x6c 0x6c 0x5f 0x74 0x33 0x31 0x31 0x5f 0x79 0x33 0x5f 0x6e 0x30 0x5f 0x6c 0x31 0x33 0x35 0x5f 0x65 0x39 0x36 0x63 0x38 0x63 0x61 0x38 0x7d" \
       | tr -d '0x' \
       | xxd -r -p
     ```
   - Menggunakan Python:
     ```bash
     python3 -c "raw = '0x61 0x63 0x61 0x64 ...'; print(bytes([int(x, 16) for x in raw.split()]).decode('ascii'))"
     ```
3. Hasil dekode menampilkan string flag lengkap:
   ```text
   academy{45c11_n0_qu35710n5_1ll_t311_y3_n0_l135_e96c8ca8}
   ```
4. Verifikasi kebenaran logika konversi menggunakan skrip standalone `scripts/solve_390_ascii_numbers.py`.

---

## Flag & Verifikasi

- **Flag:** `academy{45c11_n0_qu35710n5_1ll_t311_y3_n0_l135_e96c8ca8}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 390, "flag": "academy{45c11_n0_qu35710n5_1ll_t311_y3_n0_l135_e96c8ca8}", "correct": true}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemampuan analisis representasi byte mentah, pengenalan titik kode ASCII, dan otomasi transformasi biner-ke-teks.
  - Memahami bahwa pengkodean (*encoding*) bukan bentuk enkripsi atau mekanisme perlindungan kerahasiaan (*confidentiality*). Data yang hanya dikodekan heksadesimal dapat dibaca instan oleh siapa saja tanpa kunci rahasia.
- **Mitigasi Defensif:**
  - **Jangan Mengandalkan Obfuscation/Encoding sebagai Pengamanan:** Informasi kredensial, token API, atau konfigurasi sensitif tidak boleh disimpan atau ditransmisikan hanya dengan representasi heksadesimal atau Base64.
  - **Terapkan Kriptografi Standar (NIST SP 800-175B):** Selalu gunakan algoritma kriptografi terautentikasi (seperti AES-GCM) dengan manajemen kunci terisolasi untuk data dalam transmisi maupun penyimpanan.
