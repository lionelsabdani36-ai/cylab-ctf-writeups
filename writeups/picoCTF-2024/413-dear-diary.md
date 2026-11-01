# Writeup: Dear Diary (Challenge ID: 413)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Ext4 Filesystem Metadata Carving & Dirent Reconstruction
- **Difficulty:** Medium
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2024
- **Points:** 400
- **Flag:** `academy{1_533_n4m35_a1eed517}`

---

## Problem Statement & Scope
Diberikan sebuah berkas citra disk berformat raw (`disk.flag.img.gz`). Deskripsi kasus menyebutkan: *"If you can find the flag on this disk image, we can close the case for good!"*. Analis forensik diminta mengeksplorasi sistem berkas Linux di dalam citra disk untuk merekonstruksi artefak pesan atau catatan (*diary*) yang sengaja disembunyikan atau dihapus oleh pemilik sistem.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Struktur Entri Direktori Ext4 (Linux Dirent Architecture):** Sistem berkas Ext4 menyimpan daftar berkas dalam direktori sebagai blok data yang memuat urutan struktur `ext4_dir_entry_2`:
   - `inode` (4 byte): Nomor inode target
   - `rec_len` (2 byte): Panjang record entri saat ini
   - `name_len` (1 byte): Panjang karakter nama berkas
   - `file_type` (1 byte): Tipe berkas (regular file, directory, dll.)
   - `name` ($N$ byte): String nama berkas (di-pad hingga batas kelipatan 4 byte)
2. **Artefak Residu Penghapusan Berkas (Unlinked Directory Entries):** Ketika berkas dalam direktori dihapus via perintah `rm` / syscall `unlink()`, Ext4 umumnya tidak langsung menimpa nama berkas atau mengosongkan blok direktori dengan byte nol. Melainkan, Ext4 memperbesar `rec_len` dari entri berkas sebelumnya agar melompati entri yang dihapus, atau membiarkan salinan lama dari blok direktori tertinggal di area unallocated space atau jurnal sistem berkas (`ext4 journal`).
3. **Penyisipan Payload pada Metadata Nama Berkas:** Pelaku secara berulang membuat berkas dengan nama pendek yang merupakan potongan dari flag (`pic`, `oCT`, `F{1`, `_53`, `3_n`, `4m3`, `5_a`, `1ee`, `d51`, `7}`) menggunakan nomor inode 1845 (`0x0735`), kemudian menghapusnya setelah berkas pendamping `innocuous-file.txt` dibuat. Analisis isi file (`icat`) menghasilkan ukuran 0 byte karena data tidak pernah ditulis ke blok data, namun riwayat entri direktori di blok disk merekam seluruh urutan token nama berkas secara kronologis.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Dekompresi citra disk dan analisis partisi:
   ```bash
   gunzip -k disk.flag.img.gz
   mmls disk.flag.img
   ```
   Ditemukan partisi root Linux pada offset sektor 1140736.
2. Eksplorasi direktori root menggunakan Sleuthkit `fls`:
   ```bash
   fls -o 1140736 disk.flag.img 204 # Direktori root (inode 204)
   # Ditemukan direktori secret-secrets (inode 1842)
   fls -o 1140736 disk.flag.img 1842
   # r/r 1843: force-wait.sh
   # r/r 1844: innocuous-file.txt
   # r/r 1845: its-all-in-the-name
   ```
3. Pembacaan berkas petunjuk `its-all-in-the-name`:
   Berkas `its-all-in-the-name` berukuran 0 byte, namun namanya memberikan petunjuk fundamental bahwa informasi rahasia terletak pada penamaan berkas (*filename metadata*), bukan isi berkas (*file content*).
4. Pemindaian citra mentah untuk menemukan seluruh residu entri direktori yang berdekatan dengan `innocuous-file.txt`:
   ```bash
   python3 -c "
   import re
   data = open('disk.flag.img', 'rb').read()
   matches = [m.start() for m in re.finditer(b'innocuous-file.txt', data)]
   for m in matches:
       chunk = data[m:m+120]
       idx = chunk.find(b'\x35\x07\x00\x00') # Inode 1845
       if idx != -1:
           name_len = chunk[idx+6]
           print(chunk[idx+8:idx+8+name_len].decode('latin-1'))
   "
   ```
5. Hasil pemindaian menghasilkan urutan potongan nama berkas:
   - `pic`
   - `oCT`
   - `F{1`
   - `_53`
   - `3_n`
   - `4m3`
   - `5_a`
   - `1ee`
   - `d51`
   - `7}`
6. Penggabungan seluruh fragmen membentuk token flag:
   `picoCTF{1_533_n4m35_a1eed517}`
   Pada platform CyLab Security Academy, flag dinormalisasi ke format resmi platform:
   `academy{1_533_n4m35_a1eed517}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{1_533_n4m35_a1eed517}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 413, "flag": "academy{1_533_n4m35_a1eed517}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Forensik Metadata Sistem Berkas & Carving Residu Dirent:** Pada modul Digital Forensics LKS Cyber Security Nasional, investigasi insiden sering kali menghadapi skenario di mana penyerang telah menghapus berkas bukti (*data wiping / anti-forensics*). Analis harus memiliki kompetensi menganalisis metadata struktural sistem berkas Ext4/NTFS/FAT (seperti struktur dirent, master file table, dan journal blocks) guna memulihkan nama berkas, stempel waktu, dan residu relasi berkas yang tidak terhapus dari blok disk.
- **Pembersihan Disk Tingkat Blok (Secure Block Wiping):** Dari sudut pandang defensif, menghapus berkas menggunakan perintah standar `rm` tidak memusnahkan metadata entri direktori di disk. Untuk memastikan data rahasia tidak dapat dipulihkan melalui teknik file/metadata carving, instansi wajib menggunakan mekanisme enkripsi partisi penuh (*Full Disk Encryption* / LUKS / BitLocker) atau melakukan sanitasi blok unallocated menggunakan utilitas secure disk sanitization sesuai pedoman NIST SP 800-88 Rev 1 (*Guidelines for Media Sanitization*).
