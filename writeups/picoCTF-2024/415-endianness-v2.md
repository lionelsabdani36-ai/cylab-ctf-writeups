# Writeup: endianness-v2 (Challenge ID: 415)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / File Structure & Endianness Reconstruction
- **Difficulty:** Medium
- **Author:** Junias Bonou
- **Event:** picoCTF 2024
- **Points:** 300
- **Flag:** `academy{cert!f1Ed_iNd!4n_s0rrY_3nDian_5c667703}`

---

## Problem Statement & Scope
Diberikan sebuah artefak biner `challengefile` yang dipulihkan dari arsitektur sistem komputasi 32-bit dengan susunan byte yang tidak wajar (*inverted endianness*). Sistem deteksi file (`file challengefile`) hanya mengenali artefak sebagai data biner mentah (`data`). Analis diminta merekonstruksi struktur berkas asli dan memulihkan konten rahasia yang tersimpan di dalamnya.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Konsep Endianness pada Arsitektur Komputer:** Endianness merujuk pada urutan penyimpanan byte dari kata data multikata (word) di memori fisik:
   - **Little-Endian (LE):** Byte paling tidak signifikan (*Least Significant Byte / LSB*) disimpan di alamat memori terendah (umum pada arsitektur x86/ARM standar).
   - **Big-Endian (BE):** Byte paling signifikan (*Most Significant Byte / MSB*) disimpan di alamat terendah (umum pada protokol jaringan TCP/IP dan format serialisasi biner seperti JFIF/JPEG).
2. **Inversi Word 32-bit (Dword Swap):** Ketika sebuah berkas biner standar (seperti format JFIF yang menetapkan header Big-Endian `FF D8 FF E0`) dibaca atau diserialisasi oleh subsistem 32-bit yang membalik susunan byte pada tiap kata 4-byte (dword):
   $$\text{Block}_0 = [0xE0, 0xFF, 0xD8, 0xFF] \xrightarrow{\text{Swap 4-byte}} [0xFF, 0xD8, 0xFF, 0xE0]$$
   $$\text{Block}_1 = [0x46, 0x4A, 0x10, 0x00] \xrightarrow{\text{Swap 4-byte}} [0x00, 0x10, 0x4A, 0x46] \quad (\text{"\x00\x10JF"})$$
   $$\text{Block}_2 = [0x01, 0x00, 0x46, 0x49] \xrightarrow{\text{Swap 4-byte}} [0x49, 0x46, 0x00, 0x01] \quad (\text{"IF\x00\x01"})$$
3. **Integritas Magic Bytes & Rekonstruksi Struktur Citra:** Karena korupsi bersifat mekanis dan deterministik pada setiap kelipatan 4 byte, pembalikan urutan (*byte-order swap*) pada setiap blok 32-bit mengembalikan penanda awal (*Start of Image / SOI*), segmen APP0, tabel kuantisasi DQT, serta penanda akhir berkas (*End of Image / EOI* `FF D9`) secara sempurna.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis awal byte pertama dari berkas:
   ```bash
   head -c 16 challengefile | xxd
   # 00000000: e0ff d8ff 464a 1000 0100 4649 0100 0001
   ```
2. Identifikasi tanda pengenal JPEG JFIF (`\xff\xd8\xff\xe0\x00\x10JFIF`) yang terbalik pada setiap blok 4 byte.
3. Eksekusi skrip transformasi Python untuk membalik urutan tiap blok 4 byte:
   ```python
   with open('challengefile', 'rb') as f:
       data = f.read()

   pad = (4 - (len(data) % 4)) % 4
   padded = data + b'\x00' * pad

   out = bytearray()
   for i in range(0, len(padded), 4):
       out.extend(padded[i:i+4][::-1])

   with open('restored.jpg', 'wb') as f:
       f.write(out[:len(data)])
   ```
4. Verifikasi format berkas yang dipulihkan:
   ```bash
   file restored.jpg
   # restored.jpg: JPEG image data, JFIF standard 1.01, baseline, 300x150, components 3
   ```
5. Buka citra menggunakan penampil gambar atau konversi ke PNG dan baca teks grafis pada gambar:
   $$\text{academy\{cert!f1Ed\_iNd!4n\_s0rrY\_3nDian\_5c667703\}}$$

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{cert!f1Ed_iNd!4n_s0rrY_3nDian_5c667703}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 415, "flag": "academy{cert!f1Ed_iNd!4n_s0rrY_3nDian_5c667703}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pemahaman Representasi Memori Rendah (Low-Level Memory Order):** Dalam modul Forensik Digital LKS Cyber Security, analis sering menghadapi data artefak dari dump memori, firmware router embedded (MIPS Big-Endian vs ARM Little-Endian), atau raw block storage. Mengidentifikasi pola pembalikan byte berdasarkan *magic numbers* standar (seperti JPEG, ELF, PE, PDF, ZIP) adalah keterampilan krusial.
- **Standarisasi Serialisasi Jaringan (Network Byte Order):** Pada pengembangan perangkat lunak jaringan, selalu gunakan fungsi konversi standar seperti `htons()`, `htonl()`, `ntohs()`, dan `ntohl()` untuk memastikan konsistensi transmisi data multikata antar arsitektur sistem yang berbeda tanpa memicu korupsi format biner.
