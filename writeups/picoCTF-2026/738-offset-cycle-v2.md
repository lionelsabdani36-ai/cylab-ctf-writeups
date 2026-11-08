# Writeup: offset-cycleV2 (Challenge ID: 738)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2026
- **Points:** 400
- **Author:** Aditya Sudhansu
- **Flag:** `academy{Y0U_AGa1n_Us3d_pwNt00L5_c658ff0e}`

---

## Problem Statement & Scope
Tantangan `offset-cycleV2` menyajikan lingkungan pengujian berbasis SSH di mana peserta harus mengeksploitasi program secara dinamis dalam batas waktu 80 detik (*race against time*).
Pada direktori kerja target, skrip SUID `./start` memilih berkas kode sumber C secara acak dari repositori terproteksi `CodeBank/` (seperti `3.c`), mengompilasinya menjadi berkas ELF biner 32-bit SUID root (misalnya `./3`), dan memberikan waktu 80 detik sebelum berkas dihapus secara otomatis. Berkas rahasia `CodeBank/flag.txt` hanya dapat dibaca oleh pemilik root.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Stack Buffer Overflow via Unbounded Count (CWE-121):**
   Fungsi `vuln()` mengalokasikan buffer stack `char buf[258]`. Program meminta pengguna memasukkan jumlah byte yang ingin dibaca melalui string `input` yang kemudian diparsing menggunakan `sscanf(input, "%d", &count)`. Selanjutnya fungsi memanggil `read(0, buf, count)`. Karena tidak ada batasan nilai maksimum pada variabel `count`, penyerang dapat menentukan jumlah byte pembacaan melampaui kapasitas 258 byte untuk menimpa memori stack di sekitarnya.

2. **Kelemahan Desain Canary Kustom (CWE-323 / CWE-330):**
   Aplikasi mengimplementasikan mekanisme pengecekan integritas memori stack secara manual (bukan proteksi bawaan GCC):
   ```c
   void load_canary() {
       FILE *f = fopen("CodeBank/flag.txt", "r");
       fread(global_canary, 1, CANARY_SIZE, f);
       fclose(f);
   }
   ```
   Canary diisi dengan 4 byte pertama dari berkas `CodeBank/flag.txt`.
   Karena seluruh flag pada platform CyLab Security Academy menggunakan standar format `academy{...}`, 4 karakter pertama dari berkas flag selalu bernilai deterministik:
   $$\text{Canary} = \text{"acad"} = \text{0x61636164}$$
   Hal ini menggagalkan fungsi keamanan canary karena nilai rahasianya dapat ditebak secara pasti tanpa memerlukan kebocoran memori (*memory leak*).

3. **Ret2Win & SUID Privilege Retention (CWE-250):**
   Binary dikompilasi tanpa proteksi PIE (`No PIE`, basis memori tetap `0x08048000`) dan memiliki fungsi `win()` pada alamat statis `0x08049226`. Fungsi `win()` membuka `CodeBank/flag.txt` menggunakan `fopen()`, membaca seluruh isi flag, dan mencetaknya ke layar. Karena biner memiliki bit SUID root (`-rwsr-xr-x 1 root root`), eksekusi `win()` mempertahankan izin root untuk mengakses berkas flag yang diproteksi.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Stack Frame & Geometri Memori:**
   Pemeriksaan pembongkaran kode mesin (`objdump -d -M intel 3`) pada fungsi `vuln()`:
   - Alokasi stack: `sub esp, 0x214`
   - Posisi `buf`: `[ebp - 0x112]` (offset 0)
   - Posisi `local_canary`: `[ebp - 0x10]`
   - Jarak `buf` ke `local_canary`: $0x112 - 0x10 = 0x102 = 258$ byte.
   - Posisi `saved ebp`: `[ebp]` (offset 258 + 4 + 12 = 274 byte).
   - Posisi `saved eip`: `[ebp + 4]` (offset 278 byte).
   - Selisih padding dari akhir canary ke return address: 16 byte (variabel lokal + saved ebx + saved ebp).

2. **Penyusunan Payload Eksploitasi:**
   - **Padding Buffer:** 258 byte karakter `'A'`.
   - **Bypass Canary:** 4 byte string `"acad"`.
   - **Stack Frame Alignment:** 16 byte karakter `'B'`.
   - **Saved Return Address:** 4 byte alamat `win()` (`0x08049226`).
   Total panjang payload: $258 + 4 + 16 + 4 = 282$ byte.

3. **Eksekusi Eksploitasi pada Sesi SSH Container:**
   - Sambungkan ke layanan instance melalui SSH (`ssh -p 42553 ctf-player@xebec.cylabacademy.net`).
   - Jalankan generator `./start` untuk mengompilasi biner target `./3`.
   - Kirimkan panjang masukan `282\n` diikuti paket payload biner.
   - Validasi canary `memcmp(local_canary, global_canary, 4)` sukses dan mencetak `Ok... Now Where's the flag?`.
   - Fungsi `vuln()` melakukan `ret` langsung ke alamat `win()`, menghasilkan token bendera:
     ```
     academy{Y0U_AGa1n_Us3d_pwNt00L5_c658ff0e}
     ```

---

## Flag & Verifikasi
- **Flag Resmi Live CyLab:** `academy{Y0U_AGa1n_Us3d_pwNt00L5_c658ff0e}`
- **Native PicoCTF Archive Flag:** `picoCTF{Y0U_AGa1n_Us3d_pwNt00L5_45fb3e0b}`
- **Status Submisi REST API:** HTTP 201 Created (`"correct": true`, `"historical": false`).
- **Skrip Solver Reproduktif:** `scripts/solve_738_offset_cycle_v2.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Gunakan Stack Canaries Acak Berbasis Hardware/OS (-fstack-protector-strong):**
   Jangan pernah menggunakan secret berbasis data statis, prefix protokol, atau string yang dapat diprediksi sebagai nilai canary. Mekanisme canary GCC mengambil entropi acak dari `gs:0x14` / `fs:0x28` yang mengandung byte `\x00` untuk mencegah bypass berbasis string terminasi.
2. **Validasi Batas Input Terhadap Ukuran Buffer Aktual:**
   Pastikan variabel panjang yang diizinkan dibatasi secara tegas:
   ```c
   if (count > sizeof(buf)) {
       puts("Input count exceeds buffer boundary!");
       exit(1);
   }
   ```
3. **Pengaktifan Full ASLR & PIE (Position Independent Executable):**
   Kompilasi dengan `-fPIE -pie` memastikan seluruh alamat fungsi teks (termasuk fungsi sensitif atau `win`) diacak saat runtime, meniadakan teknik ret2win langsung tanpa adanya memory leak sebelumnya.
