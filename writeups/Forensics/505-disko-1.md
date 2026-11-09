# Writeup: DISKO 1 (Challenge ID: 505)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Raw Disk Image Bulk String Carving & Triage
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** Darkraicg492
- **Event:** General
- **Flag (Resmi CyLab):** `academy{1t5_ju5t_4_5tr1n9_19d7626c}`
- **Flag Platform Asli:** `picoCTF{1t5_ju5t_4_5tr1n9_19d7626c}`
- **Flag Komunitas:** `CTF{1t5_ju5t_4_5tr1n9_19d7626c}`
- **Standar Referensi:** NIST SP 800-115 §4.1/4.2 (Technical Flaw Discovery & Forensic Triage), NIST SP 800-88 Rev. 1 (Guidelines for Media Sanitization), CWE-312 (Cleartext Storage of Sensitive Information), & CWE-226 (Sensitive Information in Resource Not Removed Before Reuse).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Digital Forensics & Incident Response Triage*, peserta dilatih dalam teknik pemindaian cepat bukti digital mentah (*raw image triage*), ekstraksi pola biner linier (*linear carving*), dan mitigasi kegagalan sanitasi media penyimpanan berstandar NIST SP 800-88:
- **Skenario Tantangan:** Diberikan berkas citra disk mentah terkompresi `disko-1.dd.gz` (~100 MB saat didekompresi). Peserta diminta mencari artefak bendera yang tersembunyi di dalam media penyimpanan fisik tersebut.
- **Deskripsi Soal:** *"Can you find the flag in this disk image? Download the disk image disko-1.dd.gz. Hints: Maybe Strings could help? If only there was a way to do that?"*
- **Tautan Artefak CDN:**
  `https://challenge-files.cylabacademy.net/library/ec407404f30c398e6779a1126e6d620b2c86b5f9e14afa720f70614a4e0a21bf/disko-1.dd.gz`
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis karakteristik citra disk mentah (*bit-stream raw image* `.dd`).
  2. Penerapan metodologi *Rapid Forensic Triage* sesuai NIST SP 800-115 Bagian 4.2 untuk menemukan artefak tanpa rekonstruksi penuh sistem berkas.
  3. Pemindaian aliran biner terkompresi secara efisien menggunakan regex pattern matching.
  4. Penentuan offset biner absolut ditemukannya artefak (`Offset: 29779344`).
  5. Verifikasi dan validasi submisi live via CyLab REST API `POST /api/submissions/` (HTTP 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Citra Disk Mentah (*Raw Bit-Stream Image*):**
   Berkas biner `.dd` merupakan hasil salinan bit-demi-bit (*forensic bit-stream duplicate*) dari seluruh sektor media penyimpanan fisik (seperti Hard Disk Drive atau USB Flash Drive).
   Citra ini mencakup:
   - Sektor teralokasi (*allocated clusters* / berkas aktif).
   - Sektor tidak teralokasi (*unallocated space* / berkas yang telah dihapus).
   - Area sisa sektor (*slack space*).
   - Ruang partisi tersembunyi atau tabel metadata sistem berkas.

2. **Kegagalan Sanitasi Media Penyimpanan (CWE-226 & NIST SP 800-88 Rev. 1):**
   Penghapusan berkas melalui antarmuka sistem operasi standar (seperti `rm` di Linux atau tombol Delete di Windows) hanya melepaskan pointer metadata (tabel partisi, FAT cluster chain, atau inode ext4).
   Kelemahan keamanan terjadi ketika:
   - Konten muatan (*payload data*) pada sektor penyimpanan fisik tidak ditimpa (*overwritten*) dengan nilai nol atau pola acak.
   - Sesuai standar **NIST SP 800-88 Rev. 1 (Guidelines for Media Sanitization)**, media yang melepaskan data sensitif tanpa proses *Clear/Purge* (seperti `shred`, `dd if=/dev/urandom`, atau *ATA Secure Erase*) menyebabkan data tetap bertahan dalam bentuk teks biasa (*plaintext remanence*).
   - Celah ini diklasifikasikan sebagai CWE-226 (*Sensitive Information in Resource Not Removed Before Reuse*) dan CWE-312 (*Cleartext Storage of Sensitive Information*).

3. **Metodologi Triase Forensik Cepat (*Rapid Bulk String Triage* - NIST SP 800-115 §4.2):**
   Dalam investigasi forensik tanggap insiden (*Incident Response*), analis menghadapi batasan waktu yang ketat. Sebelum melakukan rekonstruksi direktori yang memakan waktu lama, pemindaian kata kunci (*keyword search*) langsung terhadap aliran byte mentah adalah prosedur standar untuk mengidentifikasi keberadaan token kredensial, kunci kriptografi, atau identitas korban.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Unduh dan Persiapan Citra Disk:**
   Mengunduh citra dari repositori artefak CyLab:
   ```bash
   curl -sL "https://challenge-files.cylabacademy.net/library/ec407404f30c398e6779a1126e6d620b2c86b5f9e14afa720f70614a4e0a21bf/disko-1.dd.gz" -o disko-1.dd.gz
   gunzip -k disko-1.dd.gz
   ```
   Citra mentah `disko-1.dd` memiliki ukuran tepat 104,857,600 byte (100 MiB / 204,800 sektor).

2. **Ekstraksi String Forensik Cepat (CLI Pipeline):**
   Menjalankan `strings` dengan penyaringan ekspresi reguler:
   ```bash
   strings disko-1.dd | grep "academy{"
   ```
   Atau menggunakan `grep` biner langsung untuk mengidentifikasi offset byte:
   ```bash
   grep -a -b -o "academy{[^}]*}" disko-1.dd
   ```
   Keluaran:
   ```text
   29779344:academy{1t5_ju5t_4_5tr1n9_19d7626c}
   ```
   Offset absolut menunjukkan bahwa bendera berada pada byte ke-`29779344` (sektor `58162`, offset dalam sektor `400`).

3. **Pemeriksaan Konteks Sektor di Sekitar Token:**
   Menggunakan `hexdump` atau `xxd` untuk memverifikasi sektor:
   ```bash
   xxd -s 29779300 -l 100 disko-1.dd
   ```
   Keluaran heksadesimal mengonfirmasi string tersimpan sebagai teks biasa ASCII murni.

4. **Eksekusi Solver Python Otomatis:**
   Skrip `scripts/solve_505_disko_1.py` memindai citra secara langsung baik dari berkas terkompresi `disko-1.dd.gz` secara *streaming* maupun dari berkas mentah `.dd`:
   ```bash
   python3 scripts/solve_505_disko_1.py disko-1.dd.gz
   ```
   Keluaran:
   ```text
   [*] Memindai aliran terkompresi GZIP: disko-1.dd.gz...
   [+] Flag ditemukan pada perkiraan offset byte 29779344: academy{1t5_ju5t_4_5tr1n9_19d7626c}
   [+] Integritas token terverifikasi 100%: academy{1t5_ju5t_4_5tr1n9_19d7626c}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{1t5_ju5t_4_5tr1n9_19d7626c}`
- **Flag Platform Asli:** `picoCTF{1t5_ju5t_4_5tr1n9_19d7626c}`
- **Flag Komunitas:** `CTF{1t5_ju5t_4_5tr1n9_19d7626c}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 505, "flag": "academy{1t5_ju5t_4_5tr1n9_19d7626c}", "correct": true, "historical": false}
  ```
  Permintaan submisi menghasilkan respons HTTP 201 Created dengan atribut `"correct": true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kepatuhan Prosedur Sanitasi Media (NIST SP 800-88 Rev. 1):**
   - Sebelum media penyimpanan (hard disk, solid-state drive, removable media) dipindahtangankan, dialokasikan ulang (*re-provisioning*), atau dipensiunkan (*decommissioning*), wajib dilakukan prosedur sanitasi media:
     * **Clear:** Penimpaan seluruh blok logis yang dapat diakses pengguna menggunakan nilai nol atau urutan pseudorandom (misal utilitas `shred -n 3` atau `blkdiscard` pada SSD).
     * **Purge:** Eksekusi perintah firmware internal seperti *ATA Secure Erase* atau *Cryptographic Erase (CE)*.
     * **Destroy:** Pemusnahan fisik (degaussing, shredding fisik) untuk media berklasifikasi tinggi.

2. **Implementasi Full Disk Encryption (FDE):**
   - Mengaktifkan enkripsi penuh media penyimpanan pada level partisi/blok (seperti LUKS di Linux atau BitLocker di Windows) memastikan bahwa sektor-sektor yang belum terhapus sempurna atau berada di unallocated space tetap terlindungi dalam bentuk sandi kriptografis yang tidak dapat dibaca tanpa kunci dekripsi sah.

3. **Prinsip Triage LKS Cyber Security:**
   - Dalam kompetisi LKS Cyber Security, efisiensi waktu adalah faktor penentu. Kemampuan memadukan perintah pipa Linux (`grep`, `strings`, `awk`) pada fase triase awal memungkinkan penyidik memverifikasi indikasi kebocoran data dalam hitungan detik sebelum melangkah ke analisis sistem berkas yang lebih kompleks.
