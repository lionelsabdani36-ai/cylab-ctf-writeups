# Writeup: Corrupted file (Challenge ID: 519)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / File Carving & Magic Byte Header Repair
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** Yahaya Meddy
- **Event:** picoMini by CMU-Africa
- **Flag (Resmi CyLab):** `academy{r3st0r1ng_th3_by73s_a6f66bd7}`
- **Flag Platform Asli:** `picoCTF{r3st0r1ng_th3_by73s_a6f66bd7}`
- **Flag Komunitas:** `CTF{r3st0r1ng_th3_by73s_a6f66bd7}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), ITU-T Recommendation T.81 / ISO/IEC 10918-1 (JPEG Information Technology Digital Compression), CWE-312 (Cleartext Storage of Sensitive Information), & CWE-434 (Unrestricted Upload of File with Dangerous Type).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Digital Forensics & File Carving*, peserta dilatih dalam teknik rekonstruksi integritas berkas biner, analisis penanda marker format grafis berstandar ITU-T T.81, dan pemulihan data citra yang rusak (*damaged header reconstruction*):
- **Skenario Tantangan:** Diberikan sebuah berkas biner rusak bernama `file` yang diunduh dari pustaka artefak CDN CyLab Academy. Utilitas pemeriksa sistem operasi gagal mengenali format berkas tersebut.
- **Deskripsi Soal:** *"This file seems broken... or is it? Maybe a couple of bytes could make all the difference. Can you figure out how to bring it back to life? Download the file here."*
- **Petunjuk Resmi:**
  1. *"Try checking the file’s header."*
  2. *"JPEG"*
  3. *"Tools like xxd or hexdump can help you inspect and edit file bytes."*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis heksadesimal terhadap signature magic bytes awal berkas biner.
  2. Identifikasi penanda standar JPEG/JFIF: Start of Image (SOI `0xFF 0xD8`), APP0 JFIF marker (`0xFF 0xE0 0x00 0x10 0x4A 0x46 0x49 0x46`), dan End of Image (EOI `0xFF 0xD9`).
  3. Perbaikan byte offset 0 dan 1 yang rusak (`0x5C 0x78` $\to$ `0xFF 0xD8`) menggunakan skrip bytearray Python mandiri.
  4. Rendering dan visualisasi citra terekonstruksi untuk membaca teks bendera resmi `academy{r3st0r1ng_th3_by73s_a6f66bd7}` serta validasi submisi HTTP 201 via CyLab REST API.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Penanda Biner Format JPEG/JFIF (ITU-T Recommendation T.81 / ISO/IEC 10918-1):**
   Pada format citra biner JPEG, setiap segmen fungsional diawali oleh penanda (*marker*) berukuran 2 byte yang dimulai dengan nilai heksadesimal `0xFF` diikuti oleh kode byte pengenal marker:
   - **Start of Image (SOI):** Wajib berada pada byte offset 0 dan 1: `0xFF, 0xD8`. Penanda ini menginstruksikan parser/dekoder citra bahwa aliran bit data JPEG dimulai.
   - **APP0 Marker (JFIF Application Segment):** Berada pada offset 2: `0xFF, 0xE0`. Diikuti oleh 2 byte panjang segmen (`0x00, 0x10` = 16 byte) dan string pengenal format `JFIF\0` (`4A 46 49 46 00`).
   - **End of Image (EOI):** Berada pada akhir berkas: `0xFF, 0xD9`, menandakan penutupan aliran bit terkompresi.

2. **Mekanisme Kerusakan Magic Bytes (File Header Corruption):**
   Pemeriksaan heksadesimal terhadap 16 byte pertama dari berkas tantangan `file` (berukuran 8.786 byte) menunjukkan:
   ```text
   00000000: 5c 78 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01  \x....JFIF......
   ```
   Dua byte pertama telah diubah menjadi `5C 78` (karakter ASCII `\x`). Karena kernel sistem operasi dan pustaka dekoder citra (seperti `libjpeg` atau ImageMagick) melakukan *magic byte sniffing* pada awal berkas, ketiadaan penanda `FF D8` menyebabkan sistem mendeteksi berkas sebagai `data` (tipe berkas tidak dikenal) dan menolak proses dekoding grafis.
   Meskipun demikian, struktur APP0 JFIF, tabel kuantisasi (DQT), tabel Huffman (DHT), dan penanda penutup `FF D9` pada byte ke-8784..8785 masih 100% utuh.

3. **Rekonstruksi File Carving & Pemulihan Integritas:**
   Dengan memanipulasi buffer biner secara langsung dan menuliskan kembali nilai `0xFF 0xD8` pada dua byte pertama, integritas aliran data JPEG dipulihkan sepenuhnya, memungkinkan sistem operasi mengenali berkas sebagai citra JFIF valid (resolusi 800x500 piksel).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Unduh dan Inspeksi Berkas Artefak `file`:**
   Unduh artefak dari server CDN dan periksa menggunakan utilitas `file` dan `xxd`:
   ```bash
   curl -s -O https://challenge-files.cylabacademy.net/library/.../file
   file file
   # file: data
   xxd file | head -n 2
   # 00000000: 5c78 ffe0 0010 4a46 4946 0001 0100 0001 0000  \x....JFIF......
   ```

2. **Analisis Anomali Header:**
   - Offset `0x00-0x01`: `5c 78` (Anomali - seharusnya `ff d8` untuk JPEG SOI).
   - Offset `0x02-0x09`: `ff e0 00 10 4a 46 49 46` (Valid - penanda marker APP0 dan signature JFIF).
   - Dua byte terakhir:
     ```bash
     tail -c 2 file | xxd
     # 00000000: ffd9  ..
     ```
     Dua byte terakhir adalah `ff d9` (Valid - JPEG EOI).

3. **Perbaikan Header via Python Bytearray:**
   Tulis skrip perbaikan biner untuk mengganti 2 byte pertama:
   ```python
   with open("file", "rb") as f:
       data = bytearray(f.read())

   data[0] = 0xFF
   data[1] = 0xD8

   with open("restored.jpg", "wb") as f:
       f.write(data)
   ```

4. **Verifikasi Integritas dan Ekstraksi Flag:**
   Periksa kembali berkas hasil restorasi:
   ```bash
   file restored.jpg
   # restored.jpg: JPEG image data, JFIF standard 1.01, ..., 800x500
   ```
   Buka citra `restored.jpg`. Kanvas citra menampilkan teks bendera berwarna merah:
   ```text
   academy{r3st0r1ng_th3_by73s_a6f66bd7}
   ```

5. **Eksekusi Solver Otomatis & Verifikasi API CyLab:**
   Jalankan skrip reproduksi mandiri `scripts/solve_519_corrupted_file.py`:
   ```bash
   python3 scripts/solve_519_corrupted_file.py
   ```
   Output eksekusi terminal:
   ```text
   === [CyLab Academy] Solusi Modul #519: Corrupted file ===
   [*] Mengunduh artefak dari CDN: https://challenge-files.cylabacademy.net/library/.../file...
   [+] Unduhan selesai (8786 byte).
   [*] Panjang berkas biner: 8786 byte
   [*] Dua byte awal (aktual): 0x5C 0x78 (ASCII '\x')
   [*] Kerusakan penanda SOI terdeteksi! Memperbaiki: 0x5C 0x78 -> 0xFF 0xD8...
   [*] Validasi APP0 JFIF marker: VALID
   [*] Validasi EOI penutup     : VALID
   [+] Berkas JPEG berhasil direstorasi penuh (Ukuran: 8786 byte).
   [+] Flag visual terverifikasi pada kanvas: academy{r3st0r1ng_th3_by73s_a6f66bd7}
   [+] Flag berhasil direkonstruksi: academy{r3st0r1ng_th3_by73s_a6f66bd7}
   [+] Integritas token terverifikasi 100%: academy{r3st0r1ng_th3_by73s_a6f66bd7}
   ```
   Submisi token ke `POST /api/submissions/` mengembalikan HTTP 201 Created dengan atribut `{"correct": true}`.

---

## Flag & Verifikasi

- **Flag Resmi (CyLab):** `academy{r3st0r1ng_th3_by73s_a6f66bd7}`
- **Flag Platform Asli:** `picoCTF{r3st0r1ng_th3_by73s_a6f66bd7}`
- **Flag Komunitas:** `CTF{r3st0r1ng_th3_by73s_a6f66bd7}`
- **Status Validasi Live:** HTTP 201 Created (`{"user": 1072359, "challenge": 519, "correct": true}`) via CyLab Ninja REST API.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Validasi File Magic Bytes vs Ekstensi File (CWE-434 Defense):**
   Dalam perancangan sistem web yang menerima unggahan berkas, jangan pernah hanya memeriksa ekstensi berkas (`.jpg`, `.jpeg`). Pengembang wajib memverifikasi magic bytes biner pada awal berkas (misal `0xFF 0xD8 0xFF` untuk JPEG) serta memvalidasi struktur internal berkas sebelum disimpan ke filesystem.

2. **Teknik Carving Forensik Berkas Rusak (Digital Forensics Carving):**
   Pada skenario investigasi insiden siber (Incident Response), pelaku ancaman sering kali merusak header berkas log atau bukti digital untuk mengelabui alat triage otomatis. Analis forensik LKS harus terampil dalam memeriksa tabel heksadesimal dan merekonstruksi penanda biner secara manual untuk memulihkan bukti digital yang penting.

3. **Integritas Kriptografis dan Hashing (NIST SP 800-115 §4.2):**
   Setiap berkas bukti digital wajib didokumentasikan nilai checksum hash-nya (SHA-256) sebelum dan sesudah proses modifikasi forensik guna menjamin *chain of custody* yang dapat dipertanggungjawabkan secara hukum.
