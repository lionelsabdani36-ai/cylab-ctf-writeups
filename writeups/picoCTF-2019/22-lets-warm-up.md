# Writeup: Lets Warm Up (Challenge ID: 22)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / ASCII Character Encoding & Byte Representation
- **Difficulty:** Easy (diff=1)
- **Author:** Sanjay C/Danny Tunitis
- **Event:** picoCTF 2019
- **Points:** 50
- **Flag:** `academy{p}`

---

## Problem Statement & Scope

Tantangan menguji konversi representasi nilai bita heksadesimal ke dalam karakter alfabet standar kode ASCII:
> *"If I told you a word started with 0x70 in hexadecimal, what would it start with in ASCII? Submit your answer in our flag format. For example, if your answer was 'hello', you would submit 'academy{hello}' as the flag."*

Tujuan modul bimbingan teknis ini adalah memantapkan kompetensi dasar pembacaan representasi bita teks pada tingkatan arsitektur mesin (*character encoding translation*), esensial untuk inspeksi paket raw socket, deobfuski shellcode, dan analisis aliran data forensik.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Standar Sandi ASCII (RFC 20 / ANSI X3.4):**
   - ASCII (*American Standard Code for Information Interchange*) memetakan nilai integer 7-bit ($0$ hingga $127$ / `0x00` hingga `0x7F`) ke dalam 128 karakter yang mencakup karakter kontrol (`0x00`-`0x1F`, `0x7F`) dan karakter cetak grafis (*printable characters*, `0x20`-`0x7E`).
   - Karakter huruf kecil alfabet Latin (`a`-`z`) menempati rentang desimal $97$ hingga $122$ (`0x61` hingga `0x7A`):
     - `'a'` = `0x61` ($97_{10}$)
     - `'p'` adalah huruf ke-16 dalam alfabet ($97 + 15 = 112_{10}$).
     - Dalam heksadesimal: $112 = (7 \times 16) + 0 = 0\text{x}70$.
   - Dengan demikian, bita `0x70` berkorespondensi langsung dengan karakter cetak `'p'`.

2. **Relevansi Keamanan Sistem (NIST SP 800-115 & Binary Exploitation):**
   - Dalam pengembangan eksploitasi biner, data string teks disimpan sebagai urutan bita ASCII yang diakhiri karakter null (`0x00`).
   - Kesalahan interpretasi encoding karakter atau konversi bita tak valid (CWE-704) pada lapisan jaringan dan aplikasi dapat memicu disinkronisasi parser (*parser differentials*), HTTP request smuggling, atau lolosnya filter WAF (*Web Application Firewall*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Menggunakan Tabel ASCII / CLI Linux:**
   Menggunakan perintah `man ascii` pada lingkungan terminal Unix/Linux:
   ```text
   Oct   Dec   Hex   Char
   160   112   70    p
   ```
   Atau menggunakan perintah `printf`:
   ```bash
   printf "\x70\n"
   ```
   Keluaran:
   ```text
   p
   ```

2. **Evaluasi via Skrip Python:**
   Menggunakan fungsi bawaan `chr()` untuk mengubah integer kode bita menjadi karakter:
   ```bash
   python3 -c 'print(chr(0x70))'
   ```
   Keluaran:
   ```text
   p
   ```

3. **Penyusunan Format Flag:**
   Sesuai ketentuan, karakter `'p'` dibungkus format token:
   ```text
   academy{p}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{p}`
- **Verifikasi API Platform:** Validasi token melalui `POST /api/submissions/` berhasil diproses:
  ```json
  {"user": 1072359, "challenge": 22, "flag": "academy{p}", "correct": true, "historical": false}
  ```
  Status kode HTTP 201 Created menandakan keberhasilan otentikasi token.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Aplikasi Lapangan LKS Cyber Security:** Peserta LKS bidang Cyber Security wajib mengenali nilai hex karakter-karakter ASCII penting secara refleks: spasi (`0x20`), baris baru `\n` (`0x0A`), carriage return `\r` (`0x0D`), angka `'0'` (`0x30`), huruf besar `'A'` (`0x41`), huruf kecil `'a'` (`0x61`), kurung kurawal `'{'` (`0x7B`), `'}'` (`0x7D`), dan null byte (`0x00`). Penguasaan ini mempercepat penyusunan buffer overflow payload (seperti menghindari null-byte dalam shellcode) serta parsing data heksadesimal mentah.
- **Strategi Pengamanan Defensif:** Pastikan seluruh komponen penerima input memvalidasi encoding karakter dengan menetapkan charset eksplisit (contoh: `UTF-8` atau `ASCII-strict`). Terapkan kanonikalisasi input sebelum evaluasi keamanan guna mencegah bypass filter akibat multi-byte encoding confusion atau transmisi karakter di luar rentang printable yang diizinkan.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_22_lets_warm_up.py`.
