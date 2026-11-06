# Writeup: Disk, disk, sleuth! (Challenge ID: 113)

- Platform: CyLab Security Academy (picoCTF)
- Category: Forensics / Disk Image Analysis & Bulk String Carving
- Difficulty: Medium (diff=2)
- Author: Syreal
- Event: picoCTF 2021
- Points: 110
- Flag: `academy{f0r3ns1c4t0r_n30phyt3_6502313d}` (Komunitas: `CTF{f0r3ns1c4t0r_n30phyt3_6502313d}`)

---

## Problem Statement & Scope

Tantangan menguji teknik analisis forensik digital pada citra media penyimpanan mentah (*raw disk image*):
> *"Use `srch_strings` from the sleuthkit and some terminal-fu to find a flag in this disk image."*
> 
> File target: `dds1-alpine.flag.img.gz`
> 
> Petunjuk:
> 1. *"Have you ever used `file` to determine what a file was?"*
> 2. *"Relevant terminal-fu in Challenge Library: https://learn.cylabacademy.org/library/85"*
> 3. *"Mastering this terminal-fu would enable you to find the flag in a single command: https://learn.cylabacademy.org/library/48"*
> 4. *"Using your own computer, you could use qemu to boot from this disk!"*

Peserta diberikan arsip terkompresi Gzip yang membungkus citra partisi sistem operasi Alpine Linux. Lingkup asesmen mencakup dekompresi data, pembedahan struktur filesystem Linux (MBR/GPT partition tables), serta ekstraksi artefak teks tersembunyi pada blok memori yang dialokasikan maupun yang berada di ruang *unallocated space* / *slack space*.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Penyimpanan Informasi Sensitif dalam Teks Terang pada Citra Media (CWE-312):**
   - Berdasarkan NIST SP 800-115 (*Section 5.4: Media Analysis and Data Recovery*), data penting, kunci, atau kredensial yang tidak dienkripsi pada media penyimpanan akan tetap tersimpan secara deterministik pada sektor disk fisik.
   - Meskipun berkas telah dihapus oleh pengguna sistem operasi, penghapusan filesystem konvensional (seperti ext4 atau FAT) hanya memutus tautan inode / penanda pointer direktori, sementara deretan byte data asli tetap utuh di blok *unallocated clusters* sampai tertimpa (*overwritten*) oleh data baru.

2. **Mekanisme Bulk String Extraction & The Sleuth Kit (TSK):**
   - Peralatan forensik seperti `srch_strings` (bagian dari TSK) atau GNU `strings -a` membaca citra biner secara byte-per-byte, mengidentifikasi sekuens karakter ASCII atau Unicode yang dapat dicetak (panjang default $\ge 4$ karakter), dan menampilkan offset byte fisiknya.
   - Karena token flag mengikuti format kanonikal tertentu (`academy{...}` atau `picoCTF{...}`), teknik ekspresi reguler (*regular expression streaming*) dapat mengisolasi artefak secara instan tanpa perlu menjalankan emulasi VM penuh (seperti QEMU) ataupun melakukan mounting partisi secara manual.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Identifikasi Format Berkas:**
   - Analisis header berkas unduhan menggunakan utilitas `file`:
     ```bash
     file dds1-alpine.flag.img.gz
     # Output: dds1-alpine.flag.img.gz: gzip compressed data, was "dds1-alpine.flag.img", last modified: Tue Mar 16 00:00:00 2021, max compression, from Unix
     ```

2. **Dekompresi Citra Media:**
   - Ekstrak arsip Gzip untuk mendapatkan raw disk image:
     ```bash
     gzip -d dds1-alpine.flag.img.gz
     ```

3. **Analisis Partisi & String Carving Melalui Sleuth Kit / Strings:**
   - Sesuai panduan tantangan, utilitas `srch_strings` dapat dipadukan dengan filter `grep`:
     ```bash
     srch_strings dds1-alpine.flag.img | grep -i "academy{"
     ```
   - Sebagai alternatif praktis di lingkungan Linux standar:
     ```bash
     strings -a -t d dds1-alpine.flag.img | grep "academy{"
     ```
   - Hasil pencarian menampilkan baris teks terang:
     ```text
     academy{f0r3ns1c4t0r_n30phyt3_6502313d}
     ```

4. **Metode Efisien Zero-Disk Footprint (Python Streaming):**
   - Untuk meminimalkan beban I/O pada sistem analitik, dekompresi dan pencarian pola regex dapat dilakukan secara *in-memory streaming*:
     ```python
     with gzip.GzipFile(fileobj=resp) as gz:
         data = gz.read()
         flag = re.search(r"academy\{[^}]+\}", data.decode('latin1')).group(0)
     ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{f0r3ns1c4t0r_n30phyt3_6502313d}`
- **Flag Komunitas:** `CTF{f0r3ns1c4t0r_n30phyt3_6502313d}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 113, "flag": "academy{f0r3ns1c4t0r_n30phyt3_6502313d}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Enkripsi Media Penyimpanan Menyeluruh (Full Disk Encryption / FDE):**
   - Dalam kerangka pertahanan siber enterprise dan kurikulum LKS *Incident Response*, aset media portabel maupun server wajib dilindungi dengan teknologi enkripsi disk (seperti LUKS di Linux atau BitLocker di Windows). FDE memastikan bahwa sektor disk mentah tidak dapat dibaca di luar lingkungan sistem operasi yang terotentikasi.
2. **Prosedur Sanitasi & Penghapusan Aman (Secure Wiping / NIST SP 800-88):**
   - Standar NIST SP 800-88 (*Guidelines for Media Sanitization*) menegaskan bahwa perintah `rm` atau format filesystem standar tidak memusnahkan data. Gunakan utilitas penimpaan kriptografis (`shred -u`, `srm`, atau cryptographic erase) sebelum media didekomisioning.
3. **Relevansi Modul LKS Cyber Security:**
   - Keterampilan ekstraksi string mentah dari citra disk merupakan fondasi modul Forensik Digital (Host Forensics & Evidence Carving) pada lomba LKS Cyber Security Nasional untuk mengumpulkan barang bukti digital secara cepat sebelum memasuki analisis mendalam menggunakan Autopsy / FTK Imager.

---

## Solver Script

Solusi reproduktif tersedia pada file terlampir:
`scripts/solve_113_disk_disk_sleuth.py`
