# Writeup: Investigative Reversing 3 (Challenge ID: 83)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Reverse Engineering & LSB Steganography
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 400
- **Author:** Danny
- **Flag:** `academy{4n0th3r_L5b_pr0bl3m_00000000000007a2d9ded}`

---

## Problem Statement & Scope
Tantangan `Investigative Reversing 3` menghadirkan skenario investigasi forensik digital tingkat lanjut di mana peserta diberikan berkas biner ELF 64-bit `mystery` dan sebuah berkas citra bitmap termutasi `encoded.bmp`. Pelaku ancaman menyusupkan informasi kredensial rahasia ke dalam media pembawa dengan teknik steganografi biner berurutan sebelum mentransmisikannya keluar jaringan organisasi.

Ruang lingkup analisis meliputi pembongkaran format berkas citra bitmap BMP (Microsoft Windows Bitmap Format), dekompilasi statis alur pemrosesan bit pada biner ELF x86_64, rekonstruksi demultiplexing LSB (*Least Significant Bit*) berjarak interval (*byte interleaving cadence*), serta validasi integritas payload bukti digital sesuai metodologi pengujian keamanan **NIST SP 800-115 Section 4.3**.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyisipan Bit Tersembunyi Berpola Jarak (Interleaved LSB Steganography / CWE-312):**
   - Berkas format bitmap menyimpan data piksel tanpa kompresi (*raw uncompressed unindexed raster RGB*). Modifikasi bit paling tidak signifikan (*least significant bit* / bit 0) pada komponen warna piksel menghasilkan perbedaan intensitas warna $\Delta \le 1/256$, yang secara visual tidak terdeteksi oleh mata manusia (*imperceptible visual degradation*).
   - Berbeda dari steganografi LSB linear sederhana, biner `mystery` menerapkan pola *cadence interleaving*:
     - Untuk setiap karakter bendera (50 byte), 8 bit karakter dipecah secara Little-Endian (LSB pertama).
     - Masing-masing bit ditulis ke bit-0 dari 8 byte pembawa berurutan.
     - Tepat setelah 8 byte bit pembawa tersebut, algoritma menyisipkan 1 byte pembawa asli tanpa modifikasi sebagai pembatas (*separator padding byte*).
     - Pola blok berulang ini menghasilkan struktur $8 + 1 = 9$ byte per karakter rahasia, dengan total jendela artefak $50 \times 9 = 450$ byte mulai dari offset 723 (0x2D3).

2. **Ketiadaan Proteksi Kriptografis pada Saluran Tersembunyi (CWE-327):**
   - Alur enkapsulasi data mengandalkan konsep usang *Security by Obscurity*. Karakter bendera tidak dienkripsi menggunakan algoritma standar berkunci simetris/asimetris yang aman, melainkan hanya diuraikan secara struktural.
   - Karena jarak offset dan mekanisme penyisipan bersifat deterministik, analis forensik yang memahami struktur logika biner dapat membalikkan pemetaan data secara matematis 100% tanpa memerlukan brute-force.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Dekompilasi Biner ELF (Ghidra / IDA Pro):**
   - Fungsi `main` dan prosedur penyisipan `codedChar` pada biner `mystery` dianalisis:
     ```c
     FILE *f_flag = fopen("flag.txt", "r");
     FILE *f_orig = fopen("original.bmp", "r");
     FILE *f_out  = fopen("encoded.bmp", "w");
     
     // Salin header BMP sepanjang 723 byte
     for (i = 0; i < 723; i++) {
         fputc(fgetc(f_orig), f_out);
     }
     
     // Encoding 50 karakter flag
     for (i = 0; i < 50; i++) {
         char c = fgetc(f_flag);
         for (k = 0; k < 8; k++) {
             int pixel = fgetc(f_orig);
             int bit = (c >> k) & 1;
             fputc((pixel & 0xFE) | bit, f_out);
         }
         // Interleaving byte padding
         fputc(fgetc(f_orig), f_out);
     }
     ```

2. **Ekstraksi Jendela Aliran Bit (Stream Carving):**
   - Membaca 450 byte data piksel mulai dari offset 723 (0x2D3) pada berkas `encoded.bmp`.
   - Mengelompokkan aliran byte menjadi 50 blok yang masing-masing berukuran 9 byte.

3. **Demultiplexing Bit & Rekonstruksi Karakter:**
   - Untuk setiap blok $j \in [0, 50)$:
     - Mengambil 8 byte pertama, mengekstrak nilai LSB (`byte & 1`), dan merekonstruksi nilai biner karakter:
       $$c_j = \sum_{k=0}^{7} (\text{byte}_k \ \& \ 1) \ll k$$
     - Mengabaikan byte ke-9 sebagai padding interleaving.
   - Mengonversi nilai integer byte hasil rekonstruksi ke karakter ASCII.

4. **Validasi Skrip Otomasi Mandiri:**
   - Mengeksekusi skrip reproduktif mandiri:
     ```bash
     python3 scripts/solve_83_investigative_reversing_3.py
     ```
   - Skrip memvalidasi rekonstruksi 50 karakter string flag secara deterministik.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{4n0th3r_L5b_pr0bl3m_00000000000007a2d9ded}`
- **Komunitas Standar (CTF Format):** `CTF{4n0th3r_L5b_pr0bl3m_00000000000007a2d9ded}`
- **Status Verifikasi:** Terverifikasi 100% pada algoritma demultiplexing LSB berjarak interval.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Integritas Media Digital (Steganography Detection):**
   Dalam investigasi forensik LKS, pemeriksa harus waspada terhadap anomali distribusi nilai bit terendah (*Chi-Square Attack on LSB distribution*) pada citra bitmap atau saluran komunikasi data tak terkompresi.
2. **Penguatan Keamanan Data Sensitif:**
   Data rahasia tidak boleh hanya disamarkan melalui pola penempatan memori atau pemecahan bit. Semua data sensitif wajib diamankan menggunakan enkripsi terotentikasi (seperti AES-256-GCM) dengan manajemen kunci terisolasi sebelum disimpan atau ditransmisikan.
3. **Kepatuhan NIST SP 800-115:**
   Dokumentasi rekonstruksi artefak forensik secara bertahap dan skrip verifikasi mandiri menjamin rantai keabsahan bukti (*chain of custody*) dan reproduktifitas temuan investigasi keamanan.
