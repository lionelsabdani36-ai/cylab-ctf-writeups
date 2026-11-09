# Writeup: DISKO 4 (Challenge ID: 704)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Raw Disk Carving & Unallocated Space Deletion Recovery
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** CyLab Forensics Team
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{d3l_d0n7_h1d3_w3ll_9748d144}`
- **Flag Komunitas:** `CTF{d3l_d0n7_h1d3_w3ll_9748d144}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), ISO/IEC 27037:2012 (Guidelines for Identification, Collection, Acquisition and Preservation of Digital Evidence), NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response), NIST SP 800-88 Rev. 1 (Guidelines for Media Sanitization), CWE-212 (Improper Removal of Sensitive Information Before Storage or Transfer), CWE-459 (Incomplete Cleanup), & MITRE ATT&CK T1070.004 (Indicator Removal: File Deletion).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis LKS Cyber Security `DISKO 4`, peserta diuji dalam melakukan pemulihan berkas terhapus (*deleted file recovery*) dan penambangan data mentah (*file carving*) dari citra media penyimpanan fisik (*raw disk image*). Modul ini merupakan tahap puncak dari seri investigasi disk forensik *DISKO* (1 sampai 4):
- **Skenario Lingkungan:** Diberikan citra mentah disk berukuran 100 MB: `704.dd` berpartisi sistem berkas Linux (ext4 / FAT).
- **Struktur Artefak:** Sebelum citra disk diakuisisi, seorang pengguna atau aktor ancaman telah melakukan penghapusan berkas arsip krusial bernama `dont-delete.gz` menggunakan perintah penghapusan standar (`rm dont-delete.gz`).
- **Anomali Operasional:**
  1. Direktori sistem berkas yang aktif tidak lagi menampilkan berkas `dont-delete.gz` pada daftar entri berkas biasa (`ls -la`).
  2. Pengguna berasumsi bahwa mengeksekusi perintah penghapusan berkas standar sistem operasi telah memusnahkan konten data dari media penyimpanan secara permanen (*anti-forensics misconception*).
- **Sasaran Pengujian:**
  1. Menganalisis metadata struktur sistem berkas dan tata letak partisi pada `704.dd`.
  2. Mengidentifikasi entri direktori yang ditandai terhapus (*deleted/unallocated directory entries*) menggunakan The Sleuth Kit (`fls -r -d`).
  3. Menemukan nomor inode yang berasosiasi dengan berkas `dont-delete.gz`.
  4. Mengekstrak dan memulihkan (*carving*) blok data mentah yang belum tertimpa menggunakan `icat` atau teknik pemindaian *magic bytes* Gzip (`\x1f\x8b\x08`).
  5. Mendekompresi aliran berkas gzip dan mengekstrak token rahasia resmi untuk divalidasi ke REST API CyLab Academy (`POST /api/submissions/`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Pemisahan Metadata dan Blok Data pada Sistem Berkas (Inode Decoupling):**
   Sistem berkas modern (ext2/3/4, FAT32, NTFS) memisahkan struktur metadata direktori dari blok penyimpanan konten aktual:
   - **Directory Entry (dirent):** Menyimpan relasi antara nama berkas teks (misal `dont-delete.gz`) dan penunjuk nomor inode.
   - **Inode Table:** Menyimpan atribut izin akses, ukuran berkas, penanda waktu MAC (*Modified, Accessed, Changed*), serta daftar penunjuk blok data langsung maupun tidak langsung (*extents/pointers*).
   - **Data Blocks:** Blok fisik/logis tempat muatan biner berkas disimpan.

2. **Mekanika Penghapusan Berkas Standar (CWE-212 / CWE-459):**
   Ketika berkas dihapus via fungsi sistem operasi (`unlink()`, `rm`):
   - Sistem operasi hanya melepaskan tautan direktori (*unlinks directory entry*) dan menurunkan pencacah referensi tautan (`i_links_count = 0`).
   - Inode ditandai sebagai bebas (*unallocated*) dalam bitmap inode.
   - Blok data yang terasosiasi ditandai sebagai dapat digunakan kembali (*free/unallocated*) dalam bitmap blok data.
   - **Sistem operasi TIDAK menimpa, menghapus, atau menolkan (zero-out) isi biner pada sektor blok data tersebut.**
   - Selama blok data unallocated belum dialokasikan untuk penulisan berkas baru, seluruh konten biner tetap tersimpan utuh di media penyimpanan.

3. **Prinsip Rekonstruksi & File Carving (ISO/IEC 27037:2012):**
   Dalam investigasi forensik, keberadaan berkas terhapus dapat diidentifikasi melalui dua pendekatan:
   - **Metadata-driven Recovery:** Jika struktur inode belum tertimpa, alat utilitas seperti The Sleuth Kit (`icat`) dapat membaca langsung rantai blok data yang sebelumnya dicatat oleh inode tersebut.
   - **Content-driven File Carving:** Jika metadata telah musnah, pemindai biner dapat mencari tanda pengenal format berkas (*magic bytes / file signatures*). Untuk arsip Gzip (RFC 1952), byte awal selalu dimulai dengan sekuens biner `1F 8B` dengan metode kompresi `08` (DEFLATE).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pemeriksaan Tata Letak Partisi Citra Disk:**
   Mengidentifikasi partisi pada citra mentah disk menggunakan `mmls` / `fdisk`:
   ```bash
   mmls 704.dd
   # Mengidentifikasi unit sektor awal partisi Linux (misalnya offset 2048 sektor atau offset sistem berkas)
   ```

2. **Enumerasi Entri Direktori yang Terhapus (The Sleuth Kit):**
   Menggunakan perintah `fls` dengan opsi `-d` (menampilkan hanya entri yang terhapus) dan `-p` (menampilkan path lengkap):
   ```bash
   fls -r -p -d -o 2048 704.dd
   ```
   Output menampilkan entri berkas yang dihapus beserta nomor inode-nya:
   ```text
   d/d * 14: dont-delete.gz
   ```
   Tanda asterik `*` mengindikasikan bahwa berkas berstatus terhapus, dengan nomor inode `14`.

3. **Ekstraksi Blok Data Unallocated Menggunakan `icat`:**
   Mengekstrak blok data mentah yang direferensikan oleh inode `14` langsung ke berkas hasil pemulihan:
   ```bash
   icat -o 2048 704.dd 14 > recovered_dont_delete.gz
   ```

4. **Dekompresi dan Pembacaan Token Rahasia:**
   Memverifikasi integritas berkas arsip menggunakan utilitas `file` dan mendekompresinya:
   ```bash
   file recovered_dont_delete.gz
   # Output: gzip compressed data, was "flag.txt", last modified: ..., max compression, from Unix
   gzip -dc recovered_dont_delete.gz
   ```
   Keluaran teks menampilkan flag rahasia secara jelas:
   ```text
   Here is your flag:
   academy{d3l_d0n7_h1d3_w3ll_9748d144}
   ```

5. **Automasi Pemulihan Skrip Python Standalone:**
   Mengimplementasikan solver mandiri (`scripts/solve_704_disko_4.py`) yang mendukung ekstraksi otomatis via Gzip stream reader, *carving* biner berbasis magic bytes `\x1f\x8b\x08` langsung dari citra raw `.dd`, serta verifikasi integritas hash token.

6. **Verifikasi Token Live CyLab REST API:**
   Mengirimkan token bukti verifikasi resmi ke REST API CyLab Academy:
   ```bash
   python3 scripts/solve_704_disko_4.py --submit
   ```
   API merespons dengan HTTP 201:
   ```json
   {"user": 1072359, "challenge": 704, "flag": "academy{d3l_d0n7_h1d3_w3ll_9748d144}", "correct": true, "historical": false}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{d3l_d0n7_h1d3_w3ll_9748d144}`
- **Flag Komunitas:** `CTF{d3l_d0n7_h1d3_w3ll_9748d144}`
- **Status Validasi:** Terverifikasi 100% via endpoint REST API `POST https://learn.cylabacademy.org/api/submissions/` (HTTP 201 Created, `correct: true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Modul LKS Cyber Security (Disk Forensics & Anti-Forensics Analysis):**
   - Dalam kompetisi LKS modul *Digital Forensics*, peserta harus mahir membedakan penghapusan logis (*file unlinking*) dari pemusnahan fisik (*data sanitization*).
   - Penguasaan utilitas forensik berbasis baris perintah (*command-line forensics*) seperti `fls`, `icat`, `blkcat`, `binwalk`, dan `foremost` wajib dilatih agar peserta tidak bergantung pada peranti lunak berbayar yang berat (seperti Autopsy GUI atau EnCase) yang membutuhkan waktu inisialisasi indeks lama.

2. **Mitigasi Pemusnahan Data Aman (Secure Media Sanitization - NIST SP 800-88 Rev. 1):**
   - **Secure Deletion Utilities:** Untuk memusnahkan berkas sensitif dari media magnetik tradisional, gunakan utilitas penghapusan aman yang menimpa sektor data dengan pola acak sebelum melakukan unlink:
     ```bash
     shred -u -z -n 3 dont-delete.gz
     # Atau menggunakan srm (secure remove):
     srm -z dont-delete.gz
     ```
   - **Solid State Drive (SSD) Considerations:** Pada media penyimpanan berbasis flash (SSD / NVMe), mekanisme *wear-leveling* internal menyebabkan perintah overwrite acak tidak selalu menimpa sel fisik yang sama. Pastikan fitur enkripsi disk penuh (*Full Disk Encryption* / FDE seperti LUKS atau BitLocker) aktif, dan kirimkan perintah ATA Secure Erase atau NVMe Format Cryptographic Erase saat media hendak di-dekomisioning.
   - **TRIM / Discard Policy:** Mengaktifkan mount flag `discard` atau menjalankan berkala `fstrim` pada SSD membantu memastikan sektor yang dilepas segera di-zeroing oleh pengendali penyimpanan (*flash controller*).
