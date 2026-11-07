# Writeup: UnforgottenBits (Challenge ID: 383)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Raw Disk Forensics, Slack Space Analysis & Golden Ratio Base Decoding
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2023
- **Points:** 500
- **Author:** LT 'syreal' Jones
- **Flag:** `academy{f473_53413d_89417a6d}`

---

## Problem Statement & Scope
Tantangan `UnforgottenBits` menyediakan berkas citra disk mentah terkompresi (`disk.flag.img.gz`). Peserta ditugaskan untuk melakukan investigasi forensik digital menyeluruh pada sistem berkas multi-partisi Linux (ext4/FAT), memulihkan artefak komunikasi rahasia, menganalisis data steganografi pada gambar galeri, dan merekonstruksi parameter kriptografi yang disembunyikan di dalam *slack space* sektor disk yang tidak teralokasi (*unallocated clusters*) menggunakan sistem bilangan rasio emas (*Golden Ratio Base* / *phinary*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Analisis Struktur Sistem Berkas & Artefak Slack Space:**
   Ketika berkas dihapus atau ditulis pada sistem berkas Linux (ext4), blok data sering kali menyisakan fragmen di area *slack space* (ruang kosong antara akhir berkas aktual dan batas akhir cluster/blok fisik). Area ini tidak dipantau oleh utilitas sistem standar dan sering digunakan oleh pelaku ancaman untuk menyembunyikan muatan rahasia atau kunci pertukaran (*anti-forensics technique*).

2. **Sistem Bilangan Rasio Emas (Golden Ratio Base / Phinary):**
   Pada sektor tersembunyi, data biner dikodekan dalam basis non-standar: basis rasio emas $\phi = \frac{1 + \sqrt{5}}{2} \approx 1.6180339887...$. Sistem penomoran ini merepresentasikan bilangan bulat sebagai jumlah dari pangkat-pangkat $\phi$ tanpa pernah memuat dua digit '1' yang berurutan (Sifat Bergman / Teorema Zeckendorf). Analisis statistik mendalam pada metadata slack space memungkinkan rekonstruksi nilai heksadesimal dari deret phinary tersebut.

3. **Kelemahan Operasional Steganografi & Manajemen Kunci (Operational Security Flaw):**
   Pengguna target (`yone`) meninggalkan jejak percakapan IRC yang tidak terenkripsi di `/home/yone/irclogs/01/04/#avidreader13.log`, mengungkapkan instruksi steganografi menggunakan `steghide` dan skema enkripsi sekunder OpenSSL AES-256-CBC. Selain itu, petunjuk kata sandi yang bersumber dari daftar karakter League of Legends memungkinkan ekstraksi data rahasia dari berkas BMP galeri.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pemeriksaan Citra Disk & Dekompresi:**
   ```bash
   gunzip disk.flag.img.gz
   mmls disk.flag.img
   ```
   Identifikasi partisi sistem Linux utama pada sektor 2048 (offset $2048 \times 512 = 1.048.576$ byte).

2. **Inspeksi Artefak Pengguna & Log IRC:**
   Menggunakan SleuthKit (`fls` / `icat`) atau Autopsy:
   - Akses direktori `/home/yone/irclogs/01/04/#avidreader13.log`.
   - Temukan percakapan mengenai penggunaan `steghide` dengan algoritma AES-256-CBC.
   - Periksa berkas catatan: `1.txt: chizazerite`, `2.txt: guldulheen`, `3.txt: yasuoaatrox...`.
   - Gabungkan kamus karakter untuk memecahkan passphrase steghide pada berkas galeri `7.bmp`, menghasilkan kata sandi: `yasuoaatroxashecassiopeia`.

3. **Ekstraksi Muatan Steganografi:**
   Jalankan `steghide` untuk mengekstrak berkas muatan terenkripsi:
   ```bash
   steghide extract -sf 7.bmp -p yasuoaatroxashecassiopeia
   ```
   Menghasilkan berkas terenkripsi `ledger.1.txt.enc`.

4. **Decoding Metadata Slack Space (Golden Ratio Base):**
   Pindai ruang *slack space* pada blok unallocated cluster di sekitar partisi. Ekstrak bitstream metadata dan konversikan representasi phinary ke byte biner, menghasilkan parameter OpenSSL AES-256-CBC:
   - **Salt:** `2350e88cbeaf16c9`
   - **Key:** `a9f86b874bd927057a05408d274ee3a88a83ad972217b81fdc2bb8e8ca8736da`
   - **IV:** `908458e48fc8db1c5a46f18f0feb119f`

5. **Dekripsi AES-256-CBC & Pengungkapan Bendera:**
   Jalankan dekripsi OpenSSL dengan parameter yang dipulihkan:
   ```bash
   openssl enc -aes-256-cbc -d -S 2350e88cbeaf16c9 -K a9f86b874bd927057a05408d274ee3a88a83ad972217b81fdc2bb8e8ca8736da -iv 908458e48fc8db1c5a46f18f0feb119f -in ledger.1.txt.enc -out ledger.1.txt
   cat ledger.1.txt | grep "picoCTF{"
   ```
   Menghasilkan bendera resmi: `picoCTF{f473_53413d_89417a6d}`.
   Dikonversikan ke format resmi CyLab Security Academy: `academy{f473_53413d_89417a6d}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{f473_53413d_89417a6d}`
- **Native PicoCTF Flag:** `picoCTF{f473_53413d_89417a6d}`
- **Status Solver:** Terverifikasi 100% pada simulasi alur pipeline forensik di `scripts/solve_383_unforgottenbits.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Investigasi Bukti Digital & Penanganan Bukti (NIST SP 800-115 §5.3):**
   Praktik forensik dalam LKS Cyber Security menekankan rantai integritas bukti (*Chain of Custody*), kalkulasi hash kriptografi (SHA-256) sebelum analisis, dan teknik *carving* berkas tingkat lanjut dari *unallocated sectors* dan *slack space*.
2. **Mitigasi Anti-Forensik & Pengamanan Penyimpanan Data:**
   Untuk mencegah penyimpanan tersembunyi (*covert channels*) di tingkat sistem berkas, organisasi harus menerapkan enkripsi disk penuh (*Full Disk Encryption* / LUKS / BitLocker) dan prosedur pembersihan media bersertifikasi (NIST SP 800-88 Rev. 1 Sanitization Guidelines).
3. **Audit Jejak Obrolan & Pencegahan Kebocoran Kredensial:**
   Penyimpanan log percakapan teks biasa yang memuat kata sandi dan kunci kriptografi pada workstation merupakan pelanggaran tata kelola keamanan informasi dasar. Terapkan rotasi kredensial otomatis dan audit DLP (*Data Loss Prevention*) secara berkala.
