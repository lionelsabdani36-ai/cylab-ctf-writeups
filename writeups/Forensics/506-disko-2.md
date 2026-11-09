# Writeup: DISKO 2 (Challenge ID: 506)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Master Boot Record (MBR) Partition Analysis & Decoy Evasion
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** Darkraicg492
- **Event:** General
- **Flag (Resmi CyLab):** `academy{4_P4Rt_1t_i5_51b913f5}`
- **Flag Platform Asli:** `picoCTF{4_P4Rt_1t_i5_51b913f5}`
- **Flag Komunitas:** `CTF{4_P4Rt_1t_i5_51b913f5}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), ANSI/INCITS 437 (Information Technology - ATA/ATAPI Command Set / MBR Partition Table), ISO/IEC 14776 (SCSI Block Commands / LBA Addressing), CWE-312 (Cleartext Storage of Sensitive Information), & CWE-398 (Indicator of Compromise Decoy Flooding / Anti-Forensics).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Digital Forensics & Storage Media Analysis*, peserta dilatih dalam parsing tabel partisi tingkat rendah (*low-level MBR parsing*), pembedahan tata letak blok LBA (*Logical Block Addressing*), dan mitigasi jebakan data umpan (*anti-forensics decoy evasion*):
- **Skenario Tantangan:** Diberikan sebuah berkas citra disk mentah terkompresi `disko-2.dd.gz` (~100 MB saat didekompresi). Analisis string global tanpa pemahaman struktur partisi menghasilkan puluhan artefak bendera palsu yang disamarkan (*decoy flags*).
- **Deskripsi Soal:** *"Can you find the flag in this disk image? The right one is Linux! One wrong step and its all gone! Download the disk image here."*
- **Tautan Artefak CDN:**
  `https://challenge-files.cylabacademy.net/library/bd18bc5adbf5b9461dca393495bee5a3ab958be1fd43e03b91c8bf103b3a23f5/disko-2.dd.gz`
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis sektor awal LBA 0 (Master Boot Record) dan pemetaan entri tabel partisi 16-byte pada offset `0x1BE`.
  2. Identifikasi pemisahan dua tipe partisi aktif: Linux Native (tipe `0x83`) vs FAT32 (tipe `0x0B`).
  3. Mengidentifikasi dan membongkar teknik umpan anti-forensik (*anti-forensics decoy flooding*) pada partisi FAT32 yang memuat 50 token jebakan.
  4. Melakukan *partition slicing / carving* terhadap sektor LBA 2048 s.d. 53247 milik partisi Linux.
  5. Ekstraksi token autentik tunggal `academy{4_P4Rt_1t_i5_51b913f5}` dan validasi submisi live via CyLab REST API `POST /api/submissions/`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Master Boot Record (MBR) & LBA (ANSI/INCITS 437):**
   Media penyimpanan berbasis partisi MBR menyimpan informasi tata letak penyimpanan pada sektor pertama (LBA 0 / offset 0..511):
   - Offset `0x000..0x1BD` (446 byte): Kode bootstrap boot loader.
   - Offset `0x1BE..0x1FD` (64 byte): Empat entri tabel partisi primer (masing-masing 16 byte).
   - Offset `0x1FE..0x1FF` (2 byte): Penanda akhir boot MBR `\x55\xAA`.
   
   Setiap entri partisi 16-byte memiliki format terstruktur:
   - Byte 0: Status boot (`0x80` = active/bootable, `0x00` = non-bootable).
   - Byte 1..3: Alamat CHS awal (Cylinder-Head-Sector).
   - Byte 4: Tipe partisi sistem berkas (*Partition Type ID*). Nilai `0x83` menandakan sistem berkas Linux Native (ext2/ext3/ext4), sedangkan `0x0B` menandakan FAT32 dengan addressing CHS/LBA.
   - Byte 5..7: Alamat CHS akhir.
   - Byte 8..11 (4 byte little-endian): Alamat sektor awal LBA (*Starting LBA sector*).
   - Byte 12..15 (4 byte little-endian): Jumlah total sektor partisi (*Number of sectors*).

2. **Dua Tata Letak Partisi pada Citra `disko-2.dd`:**
   Parsing biner terhadap MBR citra menunjukkan:
   - **Partisi 1:**
     * Tipe: `0x83` (Linux Native).
     * Start LBA: `2048` (Offset byte: $2048 \times 512 = 1,048,576$ byte = 1 MiB alignment).
     * Sektor: `51200` (Ukuran: $51200 \times 512 = 26,214,400$ byte = 25 MiB).
   - **Partisi 2:**
     * Tipe: `0x0B` (FAT32).
     * Start LBA: `53248` (Offset byte: $53248 \times 512 = 27,262,976$ byte).
     * Sektor: `65536` (Ukuran: $65536 \times 512 = 33,554,432$ byte = 32 MiB).

3. **Teknik Jebakan Data Umpan (CWE-398 / Anti-Forensic Decoy Flooding):**
   Tantangan mendesain perangkap psikologis dan otomasi:
   - Partisi kedua (FAT32) sengaja diisi dengan **50 token bendera palsu** berformat `academy{...}`.
   - Jika analis atau skrip penguji hanya menjalankan `strings disko-2.dd | grep "academy{"`, perintah tersebut akan memuntahkan 51 bendera acak tanpa petunjuk mana yang sah.
   - Instruksi soal menegaskan: *"The right one is Linux! One wrong step and its all gone!"*.
   - Hanya partisi pertama beridentitas tipe `0x83` (Linux) yang memuat **1 token bendera sah**, membuktikan bahwa investigasi forensik disk wajib berlandaskan analisis struktur volume (*volume partition triage*) alih-alih pencarian string liar tanpa konteks.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Unduh dan Dekompresi Artefak:**
   ```bash
   curl -sL "https://challenge-files.cylabacademy.net/library/bd18bc5adbf5b9461dca393495bee5a3ab958be1fd43e03b91c8bf103b3a23f5/disko-2.dd.gz" -o disko-2.dd.gz
   gunzip -k disko-2.dd.gz
   ```
   Citra mentah berukuran 104,857,600 byte (100 MiB).

2. **Inspeksi MBR Menggunakan Utilitas Partisi Linux:**
   Menggunakan `fdisk` atau `mmls` (The Sleuth Kit):
   ```bash
   fdisk -l disko-2.dd
   ```
   Keluaran:
   ```text
   Disk disko-2.dd: 100 MiB, 104857600 bytes, 204800 sectors
   Units: sectors of 1 * 512 = 512 bytes
   Sector size (logical/physical): 512 bytes / 512 bytes
   I/O size (minimum/optimal): 512 bytes / 512 bytes
   Disklabel type: dos
   Disk identifier: 0x...

   Device       Boot Start    End Sectors Size Id Type
   disko-2.dd1        2048  53247   51200  25M 83 Linux
   disko-2.dd2       53248 118783   65536  32M  b W95 FAT32
   ```

3. **Verifikasi Bahaya String Decoy Flooding:**
   Menguji pencarian string pada partisi FAT32 vs partisi Linux:
   ```bash
   python3 -c "
   import re
   with open('disko-2.dd', 'rb') as f:
       data = f.read()
   p1 = data[2048*512:53248*512]
   p2 = data[53248*512:118784*512]
   print('Partisi 1 (Linux):', len(re.findall(rb'academy\{[^}]+\}', p1)))
   print('Partisi 2 (FAT32):', len(re.findall(rb'academy\{[^}]+\}', p2)))
   "
   ```
   Hasil:
   ```text
   Partisi 1 (Linux): 1
   Partisi 2 (FAT32): 50
   ```
   Terbukti bahwa partisi FAT32 adalah jebakan berisi 50 token umpan!

4. **Carving Partisi Linux Native (Offset 2048):**
   Mengekstrak partisi Linux menggunakan `dd`:
   ```bash
   dd if=disko-2.dd of=part1_linux.raw bs=512 skip=2048 count=51200
   ```
   Mencari token bendera pada partisi yang telah diisolasi:
   ```bash
   strings part1_linux.raw | grep "academy{"
   ```
   Hasil ekstraksi:
   ```text
   academy{4_P4Rt_1t_i5_51b913f5}
   ```

5. **Eksekusi Solver Otomatis Terstandarisasi:**
   Skrip `scripts/solve_506_disko_2.py` mem-parsing MBR secara native, memotong sektor partisi Linux, dan mengekstrak bendera dalam <0.1 detik:
   ```bash
   python3 scripts/solve_506_disko_2.py disko-2.dd
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{4_P4Rt_1t_i5_51b913f5}`
- **Flag Platform Asli:** `picoCTF{4_P4Rt_1t_i5_51b913f5}`
- **Flag Komunitas:** `CTF{4_P4Rt_1t_i5_51b913f5}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 506, "flag": "academy{4_P4Rt_1t_i5_51b913f5}", "correct": true, "historical": false}
  ```
  Permintaan submisi menghasilkan respons HTTP 201 Created dengan atribut `"correct": true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Volume Layering & Partition Triage (NIST SP 800-115 §4.2):**
   - Dalam investigasi forensik media penyimpanan, analis tidak boleh langsung melompat ke pencarian kata kunci (*bulk string search*) pada level citra fisik mentah sebelum menyelesaikan triase lapisan volume (*Volume Analysis Layer*).
   - Pemetaan partisi primer, partisi tersembunyi (*hidden unallocated partitions*), partisi swap, dan sistem berkas non-standar adalah langkah wajib untuk mengisolasi bukti relevan dari gangguan data sampah atau upaya penyesatan penyidik (*honeytoken / decoy flooding*).

2. **Mitigasi Anti-Forensics & Deception Detection:**
   - Dalam konteks defensif, teknik *canary/honeytoken generation* seperti yang dicontohkan pada partisi FAT32 dapat diimplementasikan oleh tim Blue Team untuk mendeteksi keberadaan penyerang otomatis atau data scraper yang berusaha mengeksfiltrasi kredensial tanpa memahami arsitektur sistem.
   - Pihak pengembang sistem berkas dan administrator TI wajib memastikan bahwa media penyimpanan yang telah dipartisi ulang tidak meninggalkan sisa data sensitif pada sektor yang tidak teralokasi (*slack space / unallocated clusters*).

3. **Data Protection at Rest (CWE-312):**
   - Penempatan informasi rahasia pada partisi Linux tanpa enkripsi *block-level* (seperti dm-crypt/LUKS) memungkinkan siapa pun yang memperoleh salinan citra mentah untuk membaca seluruh struktur data secara langsung.
