# Writeup: Investigative Reversing 1 (Challenge ID: 27)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Multi-Artifact Reverse Engineering & Trailing Data Carving
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 350
- **Author:** Danny Tunitis
- **Flag:** `academy{An0tha_1_7a75d9ea}`

---

## Problem Statement & Scope
Tantangan `Investigative Reversing 1` merupakan eskalasi dari seri tantangan sebelumnya. Peserta diberikan satu biner ELF 64-bit `mystery` dan tiga berkas citra digital: `mystery.png`, `mystery2.png`, dan `mystery3.png`. Program biner dirancang untuk memecah berkas rahasia `flag.txt` sepanjang 26 karakter dan menyebarkan pecahan bit/karakternya ke dalam tiga wadah citra berbeda melalui penyisipan data pasca-blok `IEND`.

Ruang lingkup pengujian mencakup analisis forensik multi-wadah berkas (*multi-artifact steganographic carving*), dekompilasi perulangan perakitan memori biner x86_64, rekonstruksi pemetaan indeks karakter (*character-to-stream de-interleaving*), serta kepatuhan kerangka kerja evaluasi bukti digital **NIST SP 800-115 Section 4.3**.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pecahan Data Multisaluran (Multi-Channel Data Fragmentation / Smuggling):**
   - Penyerang mendistribusikan data sensitif ke beberapa saluran atau berkas media yang tampaknya tidak berhubungan (*sharded steganography*). Masing-masing berkas secara individual hanya memuat fragmen data parsial yang lolos dari deteksi heuristik sederhana jika dianalisis secara terisolasi.
   - Ketiga berkas memanfaatkan celah spesifikasi RFC 2083 Section 3.4 di mana data diselundupkan di belakang blok terminal `IEND`.

2. **Pola Pemetaan Deterministik Tanpa Kunci Rahasia (Insecure Obfuscation by Permutation / CWE-312):**
   - Logika pemisahan karakter dalam biner `mystery` beroperasi secara statis tanpa parameter dinamis atau garam (*salt*):
     - **Wadah 1 (`mystery.png`):** Menerima 16 byte (`flag[4]`, `flag[6..9]`, dan `flag[15..25]`).
     - **Wadah 2 (`mystery2.png`):** Menerima 2 byte terenkode (`flag[0] + 0x15` dan `flag[3] + 4`).
     - **Wadah 3 (`mystery3.png`):** Menerima 8 byte (`flag[1]`, `flag[2]`, `flag[5]`, dan `flag[10..14]`).
   - Karena setiap fragmen memiliki korespondensi posisi yang dapat dipetakan melalui dekompilasi kode mesin, rekonstruksi pesan asli dapat diselesaikan 100% secara deterministik.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Dekompilasi Biner ELF (Ghidra):**
   - Menelaah rutin fungsi `main` biner `mystery`:
     ```c
     fread(flag, 26, 1, flag_stream);
     fputc((int)flag[1], m3_stream);
     fputc((int)(char)(flag[0] + '\x15'), m2_stream);
     fputc((int)flag[2], m3_stream);
     fputc((int)flag[5], m3_stream);
     fputc((int)flag[4], m1_stream);
     for (i = 6; i < 10; i++) {
         local_6b = local_6b + '\x01';
         fputc((int)flag[i], m1_stream);
     }
     fputc((int)local_6b, m2_stream); // flag[3] + 4
     for (j = 10; j < 15; j++) {
         fputc((int)flag[j], m3_stream);
     }
     for (k = 15; k < 26; k++) {
         fputc((int)flag[k], m1_stream);
     }
     ```

2. **Ekstraksi Byte Pasca-IEND dari Ketiga Berkas:**
   - Melakukan carving byte trailing dari masing-masing berkas gambar:
     - `mystery.png`: 16 byte -> `b"ey{An1_7a75d9ea}"`
     - `mystery2.png`: 2 byte -> `b"vh"`
     - `mystery3.png`: 8 byte -> `b"cam0tha_"`

3. **Inversi Aritmatika & Penyusunan Posisi Array:**
   - Mengisi kembali array flag 26-karakter:
     - Indeks 0: `'v' - 0x15` (118 - 21) = 97 -> `'a'`
     - Indeks 1: `'c'`
     - Indeks 2: `'a'`
     - Indeks 3: `'h' - 4` (104 - 4) = 100 -> `'d'`
     - Indeks 4: `'e'`
     - Indeks 5: `'m'`
     - Indeks 6..9: `'y{An'`
     - Indeks 10..14: `'0tha_'`
     - Indeks 15..25: `'1_7a75d9ea}'`
   - String flag utuh berhasil direkonstruksi:
     `academy{An0tha_1_7a75d9ea}`

4. **Validasi Skrip Otomasi Mandiri:**
   - Eksekusi solver reproduktif:
     ```bash
     python3 scripts/solve_27_investigative_reversing_1.py
     ```
   - Seluruh byte terbukti sinkron dengan skema rekonstruksi platform.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{An0tha_1_7a75d9ea}`
- **Komunitas Standar (CTF Format):** `CTF{An0tha_1_7a75d9ea}`
- **Status Verifikasi:** Terverifikasi 100% pada de-interleaving multi-wadah biner dan pemulihan byte bergeser.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Korelasi Forensik Multi-Artefak (Correlated Evidence Analysis):**
   Dalam investigasi forensik insiden nyata (DFIR), bukti eksfiltrasi sering kali tidak ditemukan pada satu titik tunggal melainkan tersebar di beberapa artefak berkas atau alur koneksi jaringan yang berurutan. Tim analis LKS harus mampu mengkorelasikan jejak metadata dari multi-sumber secara simultan.
2. **Sanitasi File Upload & Pembersihan Data Trailing:**
   Aplikasi web yang menerima unggahan gambar harus melakukan pemrosesan ulang (*re-encoding / re-rendering*) gambar melalui pustaka grafis seperti ImageMagick atau libpng untuk memastikan seluruh data tambahan di luar blok grafis standar dibersihkan sebelum disimpan ke penyimpanan persisten.
3. **Pemberantasan Saluran Terselubung (Anti-Covert Channel Controls):**
   Menerapkan inspeksi mendalam terhadap ukuran berkas (*file size profiling*) relatif terhadap dimensi dan resolusi gambar untuk mendeteksi penambahan beban data asing secara anomali.
