# Writeup: The Office (Challenge ID: 172)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Custom Heap Allocator Canary Bypass & Use-After-Free
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 400
- **Author:** madStacks
- **Flag:** `academy{cb3b0507a278ae12d2465d4c8ee30f31}`

---

## Problem Statement & Scope
Tantangan `The Office` menyajikan biner ELF 32-bit (`the_office`) arsitektur x86 yang mengimplementasikan pengelola memori heap kustom (*custom heap allocator*) dengan sistem perlindungan berbasis *canary* inline. Penulis tantangan mengklaim mekanisme ini membuat heap "10 kali lebih aman".

Tujuan utama dalam tantangan ini adalah menemukan celah keamanan dalam logika pengelolaan heap kustom, mengatasi mekanisme proteksi heap canary, mengeksploitasi *heap buffer overflow* untuk merekayasa data entitas pengguna, serta memperoleh hak istimewa pengguna `admin` guna mengambil token akses yang memuat isi berkas `flag.txt`.

Ruang lingkup analisis audit dan pengujian kepatuhan **NIST SP 800-115 Section 4.2** (*Binary Analysis and Memory Corruption Assessment*):
1. Dekompilasi dan rekayasa balik biner yang telah di-*strip* untuk memetakan struktur data `Employee` dan fungsi alokator.
2. Identifikasi kerentanan pembacaan buffer tanpa batas (*unbounded input via scanf*) pada kolom nomor telepon (`Phone #`).
3. Analisis mekanisme pembuatan heap canary (penggunaan PRNG berbasis waktu `time(0)`).
4. Penemuan vektor kebocoran informasi (*information disclosure*) melalui penggunaan kembali memori pasca-dealokasi (*Use-After-Free / uninitialized chunk reuse*).
5. Rekonstruksi eksploitasi bertahap untuk menimpa identitas pegawai menjadi `admin` dan mengekstrak flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Heap Buffer Overflow via Unbounded `scanf("%s")` (CWE-122)
Pada fungsi penambahan pegawai (`add_employee`), masukan nomor telepon dibaca menggunakan penentu format string tanpa pembatas panjang:
```c
printf("Phone #: ");
__isoc99_scanf("%s", employee_ptr + 0x18);
```
Struktur pegawai hanya mengalokasikan ruang terbatas untuk data nomor telepon sebelum batas akhir chunk memori. Memasukkan string berukuran lebih dari 28 karakter menyebabkan byte masukan meluap (*overflow*) melewati batas chunk saat ini dan menimpa metadata serta konten dari chunk memori berikutnya di dalam heap.

### 2. Celah Perlindungan Canary & Kebocoran Memori (CWE-330 / CWE-416)
Alokator heap kustom menyisipkan nilai *canary* 32-bit di awal setiap header chunk untuk mendeteksi penimpaan buffer (*heap smashing detected*). Namun, proteksi ini cacat dalam dua aspek fundamental:
1. **Prediktabilitas PRNG (CWE-330):** Nilai canary diinisialisasi hanya sekali saat proses pertama kali mengalokasikan heap menggunakan:
   ```c
   srand(time(NULL));
   DAT_canary = rand();
   ```
   Karena seed berbasis detik kalender Unix (`time(0)`), nilai canary dapat diprediksi secara deterministik melalui brute-force offset waktu lokal.
2. **Use-After-Free / Uninitialized Memory Leak (CWE-416 / CWE-908):** Saat pegawai dihapus (`Remove employee`), alokator hanya mengubah penanda alokasi (misalnya dari `0x35` menjadi `0x34`), namun tidak mengosongkan (*zeroize*) byte memori chunk. Jika pegawai dialokasikan dengan chunk email sepanjang 24 byte lalu dihapus, alokasi pegawai berikutnya akan menempati chunk bebas tersebut. Akibat pergeseran offset, nilai canary dari chunk lama bertepatan dengan bidang bilangan bulat `Bldg #` milik pegawai baru. Menu nomor 3 (`List employees`) langsung mencetak nilai `Bldg #`, membocorkan nilai canary secara langsung dalam bentuk teks desimal.

---

## Tahapan Eksploitasi & Verifikasi (Reproduction Steps)

1. **Pemetaan Layout Heap dan Pembocoran Canary (Leak via UAF):**
   - Menambahkan pegawai #0 dengan panjang email 24 byte:
     - Masukan menu `1`, `Name: AAAA`, `Email (y/n)? y`, `Email address: AAAAAAAAAAAAAAAAAAAAAAAA`, `Salary: 255`, `Phone #: BBBB`, `Bldg: n`.
   - Menghapus pegawai #0 melalui menu `2` (ID: `0`).
   - Menambahkan dua pegawai baru (#0 dan #1) tanpa email:
     - Pegawai #0: `Name: CCCC`, `Email: n`, `Salary: 127`, `Phone #: DDDD`, `Bldg: n`.
     - Pegawai #1: `Name: EEEE`, `Email: n`, `Salary: 15`, `Phone #: FFFF`, `Bldg: n`.
   - Memilih menu `3` (`List employees`) dan membaca baris `Bldg #: <canary_int>` pada data Pegawai #1:
     $$\text{canary} = \text{int}(canary\_int)$$

2. **Rekayasa Payload Heap Buffer Overflow:**
   - Menghapus pegawai #0 kembali melalui menu `2`.
   - Mengalokasikan ulang pegawai #0 dan menyuntikkan payload eksploitasi pada masukan `Phone #`:
     - 28 byte padding sampah (`b"A" * 28`).
     - 4 byte nilai canary asli yang telah dibocorkan (`p32(canary)`).
     - 8 byte pemulihan metadata chunk (`p32(0x35) * 2`).
     - Nilai identitas target: `b"admin\x00"`.
   - Payload ini secara mulus mempertahankan integritas canary chunk pegawai #0 dan langsung menimpa nama pegawai #1 menjadi `admin`.

3. **Pengambilan Token Akses (Flag Extraction):**
   - Memilih menu `4` (`Get access token`) untuk pegawai #1.
   - Fungsi `get_access_token` memverifikasi identitas pengguna:
     ```c
     if (strncmp(employee->name, "admin", 6) == 0) {
         // Membaca dan mencetak isi flag.txt
     }
     ```
   - Pemeriksaan berhasil lolos dan bendera resmi dikeluarkan:
     `academy{cb3b0507a278ae12d2465d4c8ee30f31}`.

---

## Rekomendasi Mitigasi & Pengerasan Keamanan (Remediation)
1. **Penggunaan Masukan Terikat (Bounded Input):**
   - Ganti pemanggilan `scanf("%s", ...)` dengan fungsi masukan yang membatasi panjang buffer secara ketat, seperti `fgets(buf, sizeof(buf), stdin)` atau `scanf("%15s", ...)`.
2. **Pembersihan Memori Saat Dealokasi (Memory Sanitization):**
   - Wajib melakukan `memset(chunk_ptr, 0, chunk_size)` saat memori dibebaskan (`free`), guna mencegah kebocoran data sensitif akibat penggunaan kembali memori (*uninitialized memory use*).
3. **Penyusunan Entropi Kriptografi Kuat:**
   - Jangan gunakan `rand()` dan `time(NULL)` untuk perlindungan keamanan. Gunakan sumber entropi sistem operasi seperti `/dev/urandom` atau pemanggilan sistem `getrandom()`.

---

## Script Reproduksi
Script solver mandiri tersedia pada berkas `scripts/solve_172_the_office.py`.
Jalankan verifikasi dengan perintah:
```bash
python3 scripts/solve_172_the_office.py
```
Hasil verifikasi mengembalikan token flag valid:
`academy{cb3b0507a278ae12d2465d4c8ee30f31}`
