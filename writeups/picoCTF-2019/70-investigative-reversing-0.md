# Writeup: Investigative Reversing 0 (Challenge ID: 70)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Reverse Engineering & Trailing Data Carving
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 300
- **Author:** Danny
- **Flag:** `academy{f0und_1t_83c404e9}`

---

## Problem Statement & Scope
Tantangan `Investigative Reversing 0` memberikan dua artefak forensik: berkas biner ELF 64-bit `mystery` dan berkas gambar `mystery.png`. Analis dihadapkan pada skenario investigasi insiden di mana program misterius mengekstraksi rahasia dari sistem dan menyembunyikannya ke dalam berkas media sebelum diekfiltrasi.

Ruang lingkup pengujian mencakup analisis struktur berkas citra digital Portable Network Graphics (PNG / RFC 2083), dekompilasi statis algoritma biner ELF x86_64, pembalikan logika pergeseran aritmatika biner (*byte shifting cipher*), serta kepatuhan metodologi pengujian bukti digital berdasarkan **NIST SP 800-115 Section 4.3**.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyelundupan Data Pasca-Marker Akhir Berkas (PNG Trailing Data Smuggling / RFC 2083 Section 3.4):**
   - Struktur berkas format PNG disusun atas serangkaian blok data (*chunks*), yang secara wajib diakhiri oleh chunk `IEND` (`49 45 4E 44 AE 42 60 82`).
   - Penampil gambar standar (*image rendering engines*) menghentikan proses *decoding* tepat saat menemukan marker `IEND`. Seluruh byte data yang disisipkan setelah marker tersebut diabaikan oleh parser grafis tanpa merusak integritas visual gambar (*benign appearance*).
   - Penyerang memanfaatkan teknik *file slack / trailing data injection* ini sebagai saluran tersembunyi (*covert storage*) untuk menyembunyikan data rahasia.

2. **Kelemahan Substitusi Aritmatika Sederhana (Weak Byte-Shift Cipher / CWE-312 / CWE-327):**
   - Biner `mystery` membaca berkas `flag.txt` dan mengaburkan isi karakter menggunakan operasi penambahan/pengurangan konstan tanpa ketergantungan kunci kriptografis (*hardcoded static arithmetic*):
     - Karakter indeks 0 s.d. 5: ditulis langsung tanpa mutasi (`flag[0..5]`).
     - Karakter indeks 6 s.d. 14: ditambahkan nilai konstan `+5` (`flag[i] + 5`).
     - Karakter indeks 15: dikurangi nilai konstan `-3` (`flag[15] - 3`).
     - Karakter indeks 16 hingga akhir: ditulis langsung tanpa mutasi (`flag[16..]`).
   - Karena operasi penambahan pada gelang modulo $2^8$ bersifat bijektif dan deterministik tanpa entropi rahasia, seluruh proses enkripsi dapat dibalik secara langsung melalui pengurangan aritmatika komplementer.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Identifikasi Anomali Berkas Menggunakan ExifTool & Hexdump:**
   - Melakukan inspeksi terhadap berkas `mystery.png`:
     ```bash
     exiftool mystery.png
     ```
     ExifTool mendeteksi keberadaan *warning*: `Trailer data after PNG IEND chunk`.
   - Menggunakan hexdump untuk membaca segmen akhir berkas setelah `IEND`:
     ```bash
     xxd mystery.png | tail -n 5
     ```
     Ditemukan deretan byte trailing:
     `b"academ~\x80k5zsid6q_83c404e9}"`

2. **Analisis Dekompilasi Biner ELF (Ghidra / IDA Pro):**
   - Fungsi `main` pada biner `mystery` menunjukkan alur eksekusi berikut:
     ```c
     fseek(png_file, 0, SEEK_END);
     for (i = 0; i < 6; i++) {
         fputc(flag[i], png_file);
     }
     for (i = 6; i < 15; i++) {
         fputc(flag[i] + 5, png_file);
     }
     fputc(flag[15] - 3, png_file);
     for (i = 16; i < flag_len; i++) {
         fputc(flag[i], png_file);
     }
     ```

3. **Inversi Matematika & Rekonstruksi Flag:**
   - Membalikkan operasi secara berurutan:
     - Byte 0..5: `academ` -> `academ`
     - Byte 6..14: `~\x80k5zsid6` dikurangi 5 -> `y{f0und_1`
     - Byte 15: `q` (ASCII 113) ditambah 3 -> `t` (ASCII 116)
     - Byte 16..25: `_83c404e9}` -> `_83c404e9}`
   - Menggabungkan seluruh segmen menghasilkan string token utuh:
     `academy{f0und_1t_83c404e9}`

4. **Validasi Skrip Otomasi Mandiri:**
   - Eksekusi skrip reproduktif mandiri:
     ```bash
     python3 scripts/solve_70_investigative_reversing_0.py
     ```
   - Skrip memverifikasi integritas rekonstruksi string terhadap spesifikasi platform.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{f0und_1t_83c404e9}`
- **Komunitas Standar (CTF Format):** `CTF{f0und_1t_83c404e9}`
- **Status Verifikasi:** Terverifikasi 100% pada pembalikan byte shifting biner dan trailing data carving.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Deteksi Data Tersembunyi (File Integrity & Chunk Validation):**
   Pada gateway inspeksi berkas dan sistem DLP (*Data Loss Prevention*), terapkan validasi ketat terhadap struktur kontainer berkas RFC 2083. Sistem harus menolak atau memotong (*strip*) byte apa pun yang muncul setelah penanda resmi `IEND`.
2. **Kelemahan 'Security by Obscurity':**
   Menyembunyikan informasi berharga menggunakan pergeseran karakter sederhana (*shift cipher*) di dalam berkas media tidak memberikan perlindungan keamanan data yang nyata. Setiap data sensitif harus dienkripsi menggunakan algoritma standar industri seperti AES-GCM-256 dengan manajemen kunci berbasis HSM/KMS.
3. **Relevansi Modul LKS Cyber Security:**
   Tantangan ini melatih ketelitian peserta LKS pada domain *Digital Forensics & Reverse Engineering*, khususnya dalam membedah anomali struktur berkas citra dan membalikkan logika assembler x86_64.
