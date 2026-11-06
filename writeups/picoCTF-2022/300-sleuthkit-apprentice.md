# Writeup: Sleuthkit Apprentice (Challenge ID: 300)

- Platform: CyLab Security Academy (picoCTF)
- Category: Forensics / Multi-Partition SleuthKit Inode Extraction
- Difficulty: Medium (diff=2)
- Author: LT 'syreal' Jones
- Event: picoCTF 2022
- Points: 200
- Flag: `academy{by73_5urf3r_217f681f}` (Komunitas: `CTF{by73_5urf3r_217f681f}`)

---

## Problem Statement & Scope

Tantangan menguji keterampilan tingkat lanjut dalam analisis forensik citra disk multipartisi (*Multi-Partition Disk Forensics*):
> *"Download this disk image and find the flag.*
> 
> *Note: if you are using the webshell, download and extract the disk image into `/tmp` not your home directory.*
> - *`disk.flag.img.gz`"*

Peserta diberikan citra media penyimpanan mentah dengan beberapa partisi Linux. Berbeda dengan tantangan dasar di mana berkas berada di partisi pertama atau dapat langsung di-*carve* melalui ekspresi reguler ASCII, citra ini menyembunyikan artefak dalam partisi sekunder dan mengodekan teks bendera ke dalam format karakter lebar (*wide-character* / UTF-16) serta memicu jejak berkas terhapus (*deleted/reallocated inodes*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Analisis Partisi Lanjutan (Partition Table Mapping - NIST SP 800-115):**
   - Sesuai panduan NIST SP 800-115 (*Section 5.4: Media Analysis and Data Recovery*), seorang analis forensik tidak boleh berasumsi bahwa data penting selalu terletak pada partisi primer (`/dev/sda1`).
   - Melalui utilitas `mmls`, analis mengidentifikasi seluruh tabel partisi (MBR/GPT) yang memetakan batas blok sistem berkas, ruang pertukaran (*swap partition*), dan partisi data tambahan.
   - Pada citra ini, ditemukan 3 partisi fungsional:
     - Partisi 2 (Offset 2048): Linux Native.
     - Partisi 3 (Offset 206848): Linux Swap.
     - Partisi 4 (Offset 360448): Linux Native sekunder.

2. **Diferensiasi Metadata Inode Terhapus vs Aktif di TSK:**
   - Perintah `fls -r -o <sector>` menampilkan status entri direktori:
     - Tanda `*` dan label `(realloc)` menunjukkan berkas yang telah dihapus atau blok metadatanya telah dialokasikan ulang.
     - Inode `2082` merujuk pada `flag.txt` yang sudah terhapus (*unallocated/corrupted*).
     - Inode `2371` merujuk pada `flag.uni.txt` yang masih aktif (*allocated*) pada partisi offset 360448.

3. **Encoding Karakter UTF-16 / Wide String Bypassing:**
   - Penggunaan encoding UTF-16 Little-Endian menyisipkan byte null (`0x00`) di antara setiap karakter ASCII. Akibatnya, utilitas pencarian teks standar (`grep -a "academy{"`) gagal mendeteksi string karena tidak cocok dengan sekuens byte berdekatan. Forensik digital memerlukan ekstraksi stream inode secara langsung via `icat` diikuti normalisasi decoding UTF-16.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Dekompresi Citra Disk:**
   - Ekstrak arsip Gzip:
     ```bash
     gzip -d disk.flag.img.gz
     ```

2. **Pemetaan Tata Letak Partisi Melalui `mmls`:**
   - Eksekusi pemeriksaan tata letak sektor disk:
     ```bash
     mmls disk.flag.img
     ```
   - *Output:*
     ```text
     DOS Partition Table
     Offset Sector: 0
     Units are in 512-byte sectors

           Slot      Start        End          Length       Description
     000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
     001:  -------   0000000000   0000002047   0000002048   Unallocated
     002:  000:000   0000002048   0000206847   0000204800   Linux (0x83)
     003:  000:001   0000206848   0000360447   0000153600   Linux Swap / Solaris x86 (0x82)
     004:  000:002   0000360448   0000614399   0000253952   Linux (0x83)
     ```
   - Terdapat partisi Linux pada sektor 2048 dan sektor **360448**.

3. **Enumerasi Direktori pada Partisi 360448 Melalui `fls`:**
   - Telusuri partisi kedua secara rekursif:
     ```bash
     fls -r -o 360448 disk.flag.img | grep -i "flag"
     ```
   - *Output:*
     ```text
     ++ r/r * 2082(realloc): flag.txt
     ++ r/r 2371:            flag.uni.txt
     ```
   - Inode `2371` menyimpan berkas `flag.uni.txt`.

4. **Ekstraksi Konten Inode Melalui `icat`:**
   - Baca blok data inode 2371 pada offset sektor 360448:
     ```bash
     icat -o 360448 disk.flag.img 2371
     ```
   - *Output biner (terformat spasi/null byte):*
     ```text
      a c a d e m y { b y 7 3 _ 5 u r f 3 r _ 2 1 7 f 6 8 1 f } 
     ```

5. **Sanitasi String & Rekonstruksi Flag:**
   - Menghilangkan jeda spasi dan byte null menghasilkan token resmi:
     `academy{by73_5urf3r_217f681f}`

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{by73_5urf3r_217f681f}`
- **Flag Komunitas:** `CTF{by73_5urf3r_217f681f}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 300, "flag": "academy{by73_5urf3r_217f681f}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Strategi Multipartisi pada LKS Cyber Security:**
   - Peserta lomba LKS harus terbiasa menguji setiap partisi yang tercantum di tabel `mmls`. Membatasi investigasi hanya pada partisi pertama sering kali menjadi jebakan (*rabbit hole*) yang membuang waktu.
2. **Penanganan Variasi Encoding Forensik (UTF-16, Unicode, Base64):**
   - Bukti digital dalam investigasi nyata sering kali tersimpan dalam format UTF-16 (standar registry dan log Windows) atau stream terkompresi. Jangan mengandalkan `grep` ASCII semata; gunakan decoding multibyte.
3. **Data Remanence & Secure Erase:**
   - Keberadaan artefak pada inode terhapus `2082` membuktikan fenomena *data remanence*. Sistem enterprise wajib menerapkan *zeroing out blocks* atau penimpaan kriptografis saat menghapus data sensitif.

---

## Solver Script

Solusi reproduktif terverifikasi tersedia pada:
`scripts/solve_300_sleuthkit_apprentice.py`
