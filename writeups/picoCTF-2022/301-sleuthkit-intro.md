# Writeup: Sleuthkit Intro (Challenge ID: 301)

- Platform: CyLab Security Academy (picoCTF)
- Category: Forensics / MMLS Partition Sector Calculation & Remote TCP Validation
- Difficulty: Medium (diff=2)
- Author: LT 'syreal' Jones
- Event: picoCTF 2022
- Points: 100
- Flag: `academy{mm15_f7w!}` (Komunitas: `CTF{mm15_f7w!}`)

---

## Problem Statement & Scope

Tantangan menguji pemahaman dasar struktur sektor partisi disk dan penggunaan utilitas `mmls` dari *The Sleuth Kit* (TSK):
> *"Download the disk image and use `mmls` on it to find the size of the Linux partition. Connect to the remote checker service to check your answer and get the flag.*
> 
> *Note: if you are using the webshell, download and extract the disk image into `/tmp` not your home directory.*
> 
> *`disk.img.gz`"*

Peserta diberikan citra disk mentah terkompresi Gzip dan layanan interaktif TCP jarak jauh (*remote checker service*). Target evaluasi adalah membedah Master Boot Record (MBR), menghitung ukuran partisi sistem operasi Linux dalam satuan sektor 512-byte, serta mengirimkan jawaban secara terotentikasi ke layanan soket verifikasi untuk memperoleh flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Partisi MBR & Geometri Sektor Disk (NIST SP 800-115 Section 5.4):**
   - Dalam standar forensik NIST SP 800-115 (*Section 5.4: Media Analysis and Data Recovery*), pemahaman struktur partisi merupakan gerbang utama sebelum melakukan inspeksi sistem berkas.
   - Master Boot Record (MBR) terletak pada sektor 0 dari media penyimpanan dan mengalokasikan tabel 64-byte untuk 4 entri partisi primer. Setiap entri mencatat:
     - Status bootable (`0x80`).
     - Tipe partisi (`0x83` untuk Linux Native).
     - LBA (*Logical Block Addressing*) sektor awal (*Start Sector*).
     - Jumlah total sektor partisi (*Sector Length*).
   - Ukuran sektor standar adalah 512 byte. Mengetahui panjang sektor memungkinkan analis menentukan volume kapasitas partisi:
     $$\text{Ukuran Partisi} = \text{Length} \times 512 \text{ bytes}$$

2. **Peran Utilitas `mmls` (TSK Media Management Tool):**
   - Utilitas `mmls` mengurai *partition layout* citra disk mentah tanpa perlu me-mount atau mengubah isi disk (*read-only integrity preservation*).
   - Berbeda dengan `fdisk` yang memerlukan interaksi dinamis atau hak administratif, `mmls` beroperasi sepenuhnya di ruang pengguna (*user-space*) dan mendukung berbagai arsitektur partisi (DOS MBR, GPT, BSD disklabel, Sun slice).

3. **Verifikasi Parameter melalui Layanan Remote TCP:**
   - Server penguji mengimplementasikan protokol tanya-jawab sederhana di mana klien harus mengirimkan representasi desimal panjang sektor Linux partition. Validasi sisi server memastikan bahwa analis telah berhasil menjalankan dekompresi dan kalkulasi tabel partisi secara akurat.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Dekompresi Arsip Citra Disk:**
   - Unduh dan ekstrak citra:
     ```bash
     gzip -d disk.img.gz
     ```

2. **Eksekusi Analisis Geometri Partisi Menggunakan `mmls`:**
   - Jalankan perintah `mmls` terhadap berkas citra:
     ```bash
     mmls disk.img
     ```
   - *Output:*
     ```text
     DOS Partition Table
     Offset Sector: 0
     Units are in 512-byte sectors

           Slot      Start        End          Length       Description
     000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
     001:  -------   0000000000   0000002047   0000002048   Unallocated
     002:  000:000   0000002048   0000204799   0000202752   Linux (0x83)
     ```
   - Kolom `Length` untuk slot `002: 000:000` dengan deskripsi `Linux (0x83)` menunjukkan nilai: **202752** sektor.

3. **Koneksi ke Layanan Remote Checker & Verifikasi Jawaban:**
   - Hubungkan soket ke instance lab yang sedang aktif:
     ```bash
     nc xebec.cylabacademy.net 14590
     ```
   - Server menampilkan prompt:
     ```text
     What is the size of the Linux partition in the given disk image?
     Length in sectors: 
     ```
   - Masukkan nilai `202752`:
     ```text
     202752
     Great work!
     academy{mm15_f7w!}
     ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{mm15_f7w!}`
- **Flag Komunitas:** `CTF{mm15_f7w!}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 301, "flag": "academy{mm15_f7w!}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Integritas Bukti Digital & Non-Invasive Acquisition:**
   - Dalam standar LKS Cyber Security bidang Forensik Digital, penggunaan utilitas *non-invasive* seperti `mmls` menjamin bahwa *hash* integritas citra bukti (MD5/SHA256) tetap utuh (*forensic soundness*), berbeda dengan perintah `mount` yang dapat memperbarui timestamp *mount count* sistem berkas jika tidak dijalankan dengan opsi read-only (`-o ro,noload`).
2. **Hardening Batas Partisi & Pencegahan Partisi Tersembunyi:**
   - Sektor yang tidak dialokasikan (*unallocated sectors* antara 0 dan 2047) kerap dimanfaatkan oleh penyerang untuk menanam *bootkit* atau menyembunyikan muatan biner (*host-protected area*). Administrator sistem harus memverifikasi integritas MBR menggunakan alat audit seperti `tripwire` atau penegakan UEFI Secure Boot.
3. **Otomasi Triage Soket di Lingkungan Kompetisi:**
   - Mengintegrasikan analisis skrip (Python `socket` + `subprocess`) mempercepat pengujian soket interaktif secara instan pada babak final LKS tanpa risiko kesalahan ketik manual (*human error*).

---

## Solver Script

Solusi reproduktif terverifikasi tersedia pada:
`scripts/solve_301_sleuthkit_intro.py`
