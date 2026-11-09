# Writeup: DISKO 3 (Challenge ID: 507)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / FAT32 Filesystem, Anomaly Detection & Hidden Archive Carving
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** Darkraicg492
- **Event:** General
- **Flag (Resmi CyLab):** `academy{n3v3r_z1p_2_h1d3_2f899900}`
- **Flag Platform Asli:** `picoCTF{n3v3r_z1p_2_h1d3_2f899900}`
- **Flag Komunitas:** `CTF{n3v3r_z1p_2_h1d3_2f899900}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 1952 (GZIP File Format Specification), ISO/IEC 9293 (Information Processing - FAT32 File System Architecture), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), & CWE-312 (Cleartext Storage of Sensitive Information).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Digital Forensics & File System Analysis*, peserta dilatih dalam metodologi investigasi sistem berkas biner, deteksi anomali stempel waktu (*timestamp anomaly detection*), dan rekonstruksi arsip terkompresi tersembunyi (*hidden archive carving*):
- **Skenario Tantangan:** Diberikan sebuah berkas citra disk mentah terkompresi bernama `disko-3.dd.gz` (berukuran ~100 MB saat didekompresi). Analisis string biasa tidak langsung menampakkan flag karena data telah dikompresi dan disamarkan di antara ribuan berkas log sistem.
- **Deskripsi Soal:** *"Can you find the flag in this disk image? This time, its not as plain as you think it is! Download the disk image here."*
- **Tautan Artefak CDN:**
  `https://challenge-files.cylabacademy.net/library/b1a9c5934b8dd54058ed2cd9d58d057b0e43762f08e5fd32e04a9574fefd5939/disko-3.dd.gz`
- **Batasan Lingkungan & Scope Audit:**
  1. Identifikasi struktur sistem berkas volume mentah (MBR vs Superfloppy FAT32).
  2. Pemetaan struktur direktori `/var/log` dan analisis lini masa (timeline analysis / MACB timestamps).
  3. Identifikasi anomali metadata berkas arsip `log/flag.gz`.
  4. Ekstraksi dan dekompresi aliran RFC 1952 DEFLATE untuk memvalidasi token kompetisi.
  5. Verifikasi submisi live via CyLab REST API `POST /api/submissions/` (HTTP 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Sistem Berkas FAT32 (ISO/IEC 9293):**
   Pada berkas citra `disko-3.dd`, media diformat langsung sebagai sistem berkas FAT32 tanpa tabel partisi MBR (sering disebut sebagai format *superfloppy*).
   - Byte offset `0x00..0x02`: Instruksi lompat boot x86 (`\xEB\x58\x90`).
   - Byte offset `0x03..0x0A`: OEM Name string `mkfs.fat`.
   - BPB (BIOS Parameter Block): Menyimpan ukuran sektor (512 byte), sektor per kluster (1 sektor/kluster), serta 32 reserved sectors sebelum tabel FAT.
   - Entri direktori FAT32 berukuran 32 byte yang menyimpan nama berkas 8.3, atribut (arsip, direktori), kluster awal berkas (*high/low cluster pointer*), ukuran berkas riil dalam byte, serta stempel waktu pembuatan dan modifikasi (MS-DOS FAT date/time format).

2. **Deteksi Anomali Metadata & Timeline Forensik (NIST SP 800-115 §4.2):**
   Dalam investigasi forensik insiden siber, penyerang atau pengguna internal sering menyembunyikan artefak eksfiltrasi di dalam direktori log sistem operasi (seperti `/var/log`).
   Ketika penyidik melakukan audit lini masa (*timeline analysis*), kejanggalan stempel waktu menjadi indikator kompromi (*Indicator of Compromise / IoC*) paling nyata:
   - Ratusan berkas log sistem sah (`kern.log`, `syslog`, `dpkg.log`, `Xorg.0.log`) pada citra memiliki stempel waktu modifikasi Maret 2025 (`2025-03-31 15:31:42`).
   - Berkas mencurigakan `log/flag.gz` memiliki ukuran sangat kecil (78 byte) dengan stempel waktu `2026-09-23 01:41:04`. Selisih waktu lebih dari 1 tahun ini menandakan berkas disusupkan secara sengaja di luar operasi normal sistem operasi.

3. **Spesifikasi Aliran Kompresi GZIP (RFC 1952) & CWE-312:**
   Berkas `flag.gz` dikemas menggunakan format RFC 1952:
   - Header identifikasi 10 byte: `\x1F\x8B` (Magic ID1/ID2), `\x08` (Metode kompresi DEFLATE), `\x00` (Flags), disusul 4 byte stempel waktu MTIME dan 2 byte flag tambahan/OS.
   - Muatan data terkompresi DEFLATE (RFC 1951) diakhiri dengan CRC-32 dan ukuran data tidak terkompresi modulo $2^{32}$.
   - Data sensitif disimpan tanpa enkripsi kriptografis (CWE-312), sehingga dekompresi langsung menghasilkan teks biasa.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Unduh dan Dekompresi Citra Disk:**
   Mengunduh arsip citra disk dari CDN CyLab Academy dan mendekompresinya menjadi citra biner mentah:
   ```bash
   curl -sL "https://challenge-files.cylabacademy.net/library/b1a9c5934b8dd54058ed2cd9d58d057b0e43762f08e5fd32e04a9574fefd5939/disko-3.dd.gz" -o disko-3.dd.gz
   gunzip -k disko-3.dd.gz
   ```
   Citra biner berukuran tepat 104,857,600 byte (100 MiB).

2. **Inspeksi Struktur Sistem Berkas & Daftar Berkas:**
   Menggunakan utilitas forensik `7z` atau The Sleuth Kit (`fls`):
   ```bash
   7z l disko-3.dd
   ```
   Keluaran pemeriksaan menampilkan tipe sistem berkas:
   ```text
   Type = FAT
   File System = FAT32
   Cluster Size = 512
   ```

3. **Analisis Anomali Lini Masa (Timeline Analysis):**
   Memeriksa direktori `log/`:
   ```bash
   7z l disko-3.dd | grep -E "flag|2026-"
   ```
   Terlihat entri unik:
   ```text
   2026-09-23 01:41:04 ....A           78          512  log/flag.gz
   ```
   Ukuran terkompresi berkas hanya 78 byte, jauh lebih kecil dari arsip log sistem normal (`dpkg.log.5.gz` berukuran 259 KB).

4. **Ekstraksi Berkas dan Dekompresi RFC 1952:**
   Mengekstrak `log/flag.gz` langsung dari citra:
   ```bash
   7z e -y disko-3.dd log/flag.gz
   gzip -dc flag.gz
   ```
   Isi berkas yang didekompresi:
   ```text
   Here is your flag
   academy{n3v3r_z1p_2_h1d3_2f899900}
   ```

5. **Otomasi Carving Menggunakan Python Solver:**
   Skrip `scripts/solve_507_disko_3.py` menyediakan ekstraksi otomatis baik melalui parser 7z maupun melalui pemindaian langsung signature magic byte `\x1f\x8b\x08` pada kluster FAT32:
   ```bash
   python3 scripts/solve_507_disko_3.py disko-3.dd
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{n3v3r_z1p_2_h1d3_2f899900}`
- **Flag Platform Asli:** `picoCTF{n3v3r_z1p_2_h1d3_2f899900}`
- **Flag Komunitas:** `CTF{n3v3r_z1p_2_h1d3_2f899900}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 507, "flag": "academy{n3v3r_z1p_2_h1d3_2f899900}", "correct": true, "historical": false}
  ```
  Permintaan submisi menghasilkan respons HTTP 201 Created dengan atribut `"correct": true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **File Integrity Monitoring (FIM) & Log Isolation (CWE-200 / CWE-532):**
   - Di lingkungan operasional server Linux, direktori `/var/log` harus dipantau secara kontinu menggunakan sistem FIM (seperti Wazuh, OSSEC, atau Tripwire) dengan aturan ketat yang memperingatkan adanya penambahan berkas baru yang tidak terafiliasi dengan daemon log resmi (*unregistered binary/archive creation*).
   - Log audit harus dikirimkan secara waktu-nyata (*real-time log forwarding*) ke server SIEM/Syslog terpusat yang bersifat *append-only* (WORM - Write Once, Read Many) sehingga penyerang lokal tidak dapat menyisipkan atau memanipulasi berkas log.

2. **Prinsip Forensik Digital LKS (MACB Timestamp Triage):**
   - Dalam kompetisi LKS Cyber Security bidang Incident Response & Forensics, peserta wajib menguasai pembuatan *bodyfile* dan eksekusi `mactime` dari The Sleuth Kit untuk memetakan urutan kronologis kejadian insiden. Anomali stempel waktu sering kali merupakan petunjuk utama penemuan artefak kejahatan (*anti-forensics / timestomping evasion*).

3. **Penyimpanan Berkas Terproteksi Kriptografis (CWE-312):**
   - Kompresi data menggunakan GZIP/ZIP bukanlah mekanisme keamanan atau enkripsi. Setiap data sensitif yang disimpan pada media penyimpanan statis wajib dilindungi oleh skema enkripsi terotentikasi (seperti AES-256-GCM) dengan manajemen kunci terisolasi (KMS/HSM).
