# Writeup: Bizz Fuzz (Challenge ID: 181)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Control Flow Flattening & Stack Buffer Overflow
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 500
- **Author:** Collin Petty
- **Flag:** `academy{y0u_found_m3}`

---

## Problem Statement & Scope
Tantangan `Bizz Fuzz` menyajikan berkas biner ELF 32-bit x86 (`vuln`) yang mengimplementasikan variasi rumit dari permainan anak-anak klasik *FizzBuzz*. Pengguna dituntut memberikan respons interaktif sesuai aturan kelipatan angka (fizz untuk kelipatan 3, buzz untuk kelipatan 5, fizzbuzz untuk kelipatan 15, dan representasi angka untuk nilai lainnya). Di balik logika permainan sederhana tersebut, biner telah diobfuskasi secara intensif dengan teknik *control flow flattening* dan ratusan fungsi bersarang (*nested functions*).

Ruang lingkup audit keamanan perangkat lunak dan analisis rekayasa balik biner ini mencakup:
1. Rekonstruksi graf kendali alur (*control flow graph*) menggunakan Ghidra/IDA Pro untuk memetakan jalur eksekusi percabangan.
2. Otomasi interaksi soket jaringan untuk menjawab tantangan FizzBuzz secara terprogram hingga mencapai fungsi cabang terdalam (*leaf node*).
3. Identifikasi kerentanan pembacaan buffer yang tidak dibatasi (*unbounded read*) pada fungsi `fgets()`.
4. Perhitungan jarak offset penimpaan stack frame menuju register pencatat instruksi `$eip`.
5. Pengalihan alur kendali eksekusi secara langsung menuju fungsi tak terdokumentasi `print_flag` tanpa memerlukan ROP chain kompleks karena ketiadaan proteksi PIE.
6. Verifikasi kepatuhan pengujian keamanan berbasis standar **NIST SP 800-115 Section 4.2** (*Vulnerability Analysis and Exploitation Verification*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Obfuskasi Graf Alur Kendali (Control Flow Obfuscation)
Pengembang menyebarkan ratusan fungsi pembungkus kecil dengan struktur percabangan kompleks untuk menghambat analisis statis. Namun, seluruh fungsi tersebut bermuara pada satu fungsi target yang menyimpan kerentanan inti.

### 2. Stack-based Buffer Overflow pada Input fgets (CWE-120)
Pada fungsi daun (*leaf node*), biner mengalokasikan buffer lokal pada stack sebesar 80 byte, namun mengizinkan pembacaan input pengguna hingga ukuran yang melebihi batas buffer tersebut tanpa validasi panjang (*length checking*):
```c
char buffer[80];
fgets(buffer, 256, stdin);
```
Selain itu, kompilasi biner tidak mengaktifkan proteksi:
- **Stack Canaries:** Ditiadakan, sehingga overwrite pada return address dapat terjadi langsung tanpa memicu abort.
- **PIE (Position Independent Executable):** Dinonaktifkan, sehingga segmen teks dan fungsi berada pada alamat memori absolut tetap (`0x08048000`).

### 3. Fungsi Pemenang Tersembunyi (Win Function)
Di dalam biner terdapat fungsi mandiri pada alamat `0x08048656` (`print_flag`) yang membaca berkas `flag.txt` di server dan langsung mencetaknya ke *standard output*.

---

## Tahapan Eksploitasi & Verifikasi (Reproduction Steps)

1. **Analisis Statis & Penentuan Target:**
   - Melalui dekompilasi Ghidra, ditemukan fungsi target pada alamat `0x08048656` yang mengeksekusi:
     ```c
     FILE *f = fopen("flag.txt", "r");
     fgets(flag, sizeof(flag), f);
     puts(flag);
     ```

2. **Automasi Penelusuran Percabangan FizzBuzz:**
   - Membangun skrip automasi yang secara rekursif mengirimkan string jawaban FizzBuzz berdasarkan nomor giliran masukan:
     ```python
     def answer(n):
         if n % 15 == 0: return "fizzbuzz"
         if n % 3 == 0: return "fizz"
         if n % 5 == 0: return "buzz"
         return str(n)
     ```
   - Skrip berhasil melintasi tahapan validasi (8 fungsi -> 1 fungsi -> 22 fungsi) hingga tiba pada fungsi rentan `fgets()`.

3. **Perhitungan Offset & Konstruksi Payload:**
   - Menggunakan pola *cyclic pattern* GDB-PEDA, jarak buffer masukan menuju `$eip` teridentifikasi persis pada 95 byte.
   - Menyusun payload injeksi:
     $$\text{Payload} = \text{b"A"} \times 95 + \text{p32}(0x08048656)$$

4. **Pengiriman Payload & Ekstraksi Flag:**
   - Mengirimkan string awal validasi diikuti payload overflow.
   - Alur eksekusi melompat langsung ke `0x08048656` dan server mengembalikan token bendera:
     `academy{y0u_found_m3}`.

---

## Rekomendasi Mitigasi & Pengerasan Keamanan (Remediation)
1. **Penerapan Mitigasi Kompilasi Modern (Compiler Hardening):**
   - Kompilasi biner dengan flag proteksi lengkap: `-fstack-protector-all -fPIE -pie -Wl,-z,relro,-z,now`.
   - Mengaktifkan ASLR dan PIE mencegah penyerang memanfaatkan alamat fungsi tetap (*fixed address targets*).
2. **Penggunaan Fungsi Input Aman Terbatas (Bound-Checked Functions):**
   - Pastikan panjang input maksimum pada `fgets()` atau `read()` tidak pernah melebihi ukuran buffer yang dialokasikan:
     ```c
     fgets(buffer, sizeof(buffer), stdin);
     ```
3. **Pembersihan Dead Code & Debug Functions:**
   - Hapus seluruh fungsi pembantu atau fungsi pengujian internal seperti `print_flag` dari build rilis produksi.

---

## Script Reproduksi
Script solver mandiri tersedia pada berkas `scripts/solve_181_bizz_fuzz.py`.
Jalankan verifikasi dengan perintah:
```bash
python3 scripts/solve_181_bizz_fuzz.py
```
Hasil verifikasi mengembalikan token flag valid:
`academy{y0u_found_m3}`
