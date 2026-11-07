# Writeup: B1g_Mac (Challenge ID: 56)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / NTFS Filesystem & Metadata Carving
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 500
- **Author:** Danny
- **Flag:** `academy{M4cTim35!}`

---

## Problem Statement & Scope
Tantangan `B1g_Mac` menyajikan skenario investigasi forensik sistem berkas tingkat lanjut di mana sebuah sistem Windows yang terkompromi dicurigai menyembunyikan eksfiltrasi data tanpa meninggalkan jejak isi pada konten berkas reguler (*zero payload in standard data streams*). Pemeriksa forensik diberikan arsip direktori berisi kumpulan berkas yang diekstraksi dari volume NTFS (New Technology File System).

Ruang lingkup pengujian mencakup analisis struktur berkas internal NTFS, khususnya tabel berkas utama (*Master File Table* / $MFT), atribut `$STANDARD_INFORMATION`, manipulasi metadata stempel waktu MACB (*Modification, Access, Creation, and Entry / Birth*), rekonstruksi saluran tersembunyi (*covert timing channels*), dan penerapan standar analisis forensik digital **NIST SP 800-115 Section 4.3**.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Saluran Tersembunyi pada Resolusi Timestamp NTFS (Covert Storage Channel / CWE-312):**
   - Dalam sistem berkas NTFS, setiap stempel waktu disimpan dalam format struktur Windows `FILETIME`, yaitu bilangan bulat 64-bit tak bertanda (*64-bit unsigned integer*) yang merepresentasikan interval 100-nanodetik sejak 1 Januari 1601 UTC.
   - Setiap berkas pada tabel $MFT mencatat empat stempel waktu utama:
     - **M (Modified):** Waktu perubahan isi berkas terakhir.
     - **A (Accessed):** Waktu akses berkas terakhir.
     - **C (Changed / MFT Modified):** Waktu perubahan metadata MFT terakhir.
     - **B (Birth / Created):** Waktu pembuatan berkas pertama kali.
   - Nilai 16-bit terendah (*low-order 2 bytes* / `timestamp & 0xFFFF`) hanya mewakili durasi waktu sekitar 6,55 milidetik. Mengubah 2 byte terendah ini sama sekali tidak mengubah tampilan tanggal, jam, atau detik yang dapat dibaca manusia pada Windows Explorer (*sub-second visual stealth*).
   - Penyerang memanfaatkan celah presisi waktu ini sebagai media penyelundupan data rahasia (*timestamp slack covert channel*).

2. **Ketiadaan Integritas Kriptografis Metadata (CWE-327):**
   - Karakter flag dipetakan per 2 byte (word 16-bit) ke dalam atribut Modified Time pada berkas-berkas berurutan (`file_01` s.d. `file_09`).
   - Karena struktur metadata tidak dilindungi oleh tanda tangan digital kriptografis atau hash integritas tingkat berkas, analis forensik dapat mengekstrak kembali seluruh byte rahasia secara deterministik hanya dengan mengurai struktur biner `$STANDARD_INFORMATION`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Struktur Metadata Menggunakan The Sleuth Kit (TSK):**
   - Memeriksa direktori berkas target menggunakan peralatan TSK (`fls` dan `istat`):
     ```bash
     fls -r -m C: image.dd > bodyfile
     mactime -b bodyfile -d > timeline.csv
     ```
   - Pemeriksaan seksama pada stempel waktu beresolusi tinggi menunjukkan bahwa bagian sub-detik memiliki pola byte ASCII yang tidak wajar.

2. **Ekstraksi Nilai Biner 64-Bit FILETIME:**
   - Melakukan parsing langsung terhadap stempel waktu raw 64-bit pada setiap berkas berurutan:
     ```python
     # Membaca stempel waktu Modified (64-bit integer)
     modified_time = get_filetime_modified(file_path)
     # Ekstraksi 2 byte terendah
     embedded_word = modified_time & 0xFFFF
     ```

3. **Penyusunan Ulang Karakter (Character Reassembly):**
   - Memecah setiap kata 16-bit menjadi dua karakter ASCII:
     - `file_01.dat`: `0x6361` -> `'ac'`
     - `file_02.dat`: `0x6461` -> `'ad'`
     - `file_03.dat`: `0x6d65` -> `'em'`
     - `file_04.dat`: `0x7b79` -> `'y{'`
     - `file_05.dat`: `0x344d` -> `'M4'`
     - `file_06.dat`: `0x5463` -> `'cT'`
     - `file_07.dat`: `0x6d69` -> `'im'`
     - `file_08.dat`: `0x3533` -> `'35'`
     - `file_09.dat`: `0x7d21` -> `'!}'`
   - Menggabungkan seluruh pasangan karakter menghasilkan string token utuh:
     `academy{M4cTim35!}`

4. **Validasi Skrip Otomasi Mandiri:**
   - Mengeksekusi skrip reproduktif mandiri:
     ```bash
     python3 scripts/solve_56_b1g_mac.py
     ```
   - Skrip memverifikasi ekstraksi metadata stempel waktu NTFS dan rekonstruksi karakter secara lengkap.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{M4cTim35!}`
- **Komunitas Standar (CTF Format):** `CTF{M4cTim35!}`
- **Status Verifikasi:** Terverifikasi 100% pada ekstraksi 2 byte terendah MACB timestamp metadata NTFS.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Pemeriksaan Forensik Timestamp Resolusi Tinggi:**
   Dalam skenario investigasi insiden LKS Cyber Security, analis tidak boleh hanya mengandalkan representasi waktu tingkat detik pada antarmuka GUI. Pemeriksaan wajib melibatkan alat forensik biner tingkat rendah (*low-level parsers*) untuk mendeteksi anomali pada interval nanodetik/milidetik.
2. **Pencegahan Saluran Tersembunyi (Covert Channel Mitigation):**
   Sistem operasi dan solusi EDR (*Endpoint Detection and Response*) harus mengawasi modifikasi masif terhadap stempel waktu berkas (*timestomping*) yang dilakukan oleh proses non-sistem tanpa alasan administratif yang sah.
3. **Kepatuhan NIST SP 800-115:**
   Dokumentasi analisis struktur `$MFT` dan skrip parsing otomatis memperkuat integritas rantai pembuktian forensik dan menjamin transparansi temuan teknis.
