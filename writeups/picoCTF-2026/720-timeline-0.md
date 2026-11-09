# Writeup: Timeline 0 (Challenge ID: 720)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / ext4 Filesystem Analysis & Timestomping Outlier Detection
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** picoCTF
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{71m311n3_0u7113r_h3r_43a2e7af}`
- **Flag Komunitas:** `CTF{71m311n3_0u7113r_h3r_43a2e7af}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), ISO/IEC 27037 (Guidelines for Digital Evidence Handling), CWE-506 (Embedded Malicious Code), & SleuthKit File System Forensic Analysis Framework.

---

## Problem Statement & Scope

Pada modul bimbingan teknis tingkat dasar `Timeline 0`, peserta diajarkan prinsip fundamental investigasi forensik disk Linux menggunakan artefak rekaman linimasa metadata sistem berkas:
- Skenario lingkungan: Disediakan disk image partisi Linux berbasis ext4 terkompresi: `partition4.img.gz` (~490 MB).
- Pernyataan tantangan:
  > *"Can you find the flag in this disk image? Wrap what you find in the academy{} flag format."*
- Petunjuk resmi investigasi:
  1. *"Create a Sleuthkit MAC timeline!"*
  2. *"Sloppy timestomping can yield strange (very old) timestamps"*
- Sasaran pengujian: Mengekstrak metadata inode sistem berkas ext4 menggunakan SleuthKit (`fls` & `mactime`), menyaring linimasa untuk menemukan anomali pemalsuan waktu (*timestomping*), mengekstrak artefak tersembunyi via `icat`, merekonstruksi string rahasia terenkode Base64, dan memvalidasi token resmi pada endpoint REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Metadata Waktu Inode ext4 & Representasi Waktu Unix:**
   Sistem berkas Linux mencatat empat penanda waktu utama pada setiap inode:
   - **Modified (mtime):** Waktu modifikasi konten berkas terakhir.
   - **Accessed (atime):** Waktu akses baca berkas terakhir.
   - **Changed (ctime):** Waktu perubahan metadata status inode (izin akses, kepemilikan).
   - **Birth / Creation (crtime):** Waktu pembuatan berkas pertama kali.
   Seluruh nilai waktu disimpan dalam format Unix epoch (jumlah detik sejak 1 Januari 1970 00:00:00 UTC).

2. **Kelemahan Taktik Anti-Forensik Timestomping (CWE-506):**
   Pelaku penyerangan sering mencoba menyembunyikan berkas muatan (*payload*) atau utilitas eksploitasi di antara ribuan berkas sistem sah dengan mengubah atribut penanda waktu (*timestomping* melalui syscall `utime`/`utimensat` atau perintah shell `touch -d`).
   Namun, manipulasi manual yang ceroboh (*sloppy timestomping*) seringkali menghasilkan penanda waktu yang tidak masuk akal (misalnya mengatur tanggal modifikasi ke 1 Januari 1985). Pada sistem Linux modern yang dibangun setelah tahun 2020:
   - Tanggal sebelum pembuatan sistem operasi atau sebelum inisialisasi volume sistem berkas adalah anomali statistik ekstrem (*temporal outlier*).
   - Analisis distribusi kronologis sederhana akan langsung mengisolasi berkas tersebut di baris paling awal linimasa.

3. **Integritas Metadata versus Bukti Konten:**
   Meskipun pelaku berhasil mengubah metadata waktu modifikasi (mtime) dan akses (atime), konten berkas tetap tersimpan utuh pada blok data inode ext4. Selama blok data tersebut belum ditimpa (*overwritten*), ekstraksi langsung via inode number menggunakan alat forensik SleuthKit `icat` dapat memulihkan seluruh muatan tanpa terpengaruh manipulasi direktori sistem.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Dekompresi Artefak Citra Disk:**
   Mendekompresi berkas arsip mentah:
   ```bash
   gzip -dc partition4.img.gz > partition4.img
   ```

2. **Pembangkitan Linimasa MAC SleuthKit (Bodyfile Analysis):**
   Mengekstrak rekaman *bodyfile* dari filesystem ext4 dan mengubahnya menjadi format linimasa terurut kronologis:
   ```bash
   fls -r -m / -o 0 partition4.img | mactime -d -b - > timeline.csv
   ```

3. **Deteksi Anomali Waktu Ekstrem (Outlier Triage):**
   Memeriksa baris paling awal dari hasil linimasa `timeline.csv`:
   ```bash
   head -n 20 timeline.csv
   ```
   Ditemukan satu entri file yang sangat mencolok:
   - Tanggal: `1985-01-01 00:00:00 UTC`
   - Lokasi: `/bin/bcab`
   - Inode: `4945`
   - Ukuran: 48 byte
   Entri ini merupakan satu-satunya berkas di seluruh sistem yang memiliki timestamp pra-2020, memverifikasi keberadaan manipulasi waktu ceroboh (*timestomping*).

4. **Ekstraksi Berkas Menggunakan SleuthKit `icat`:**
   Mengekstrak blok data dari inode 4945 tanpa me-mount sistem berkas:
   ```bash
   icat -o 0 partition4.img 4945
   ```
   Diperoleh muatan ber-encoding Base64:
   `NzFtMzExbjNfMHU3MTEzcl9oM3JfNDNhMmU3YWYK`.

5. **Decoding Muatan & Rekonstruksi Flag:**
   Mendekode string Base64:
   ```bash
   echo "NzFtMzExbjNfMHU3MTEzcl9oM3JfNDNhMmU3YWYK" | base64 -d
   ```
   Hasil: `71m311n3_0u7113r_h3r_43a2e7af`.
   Membungkus hasil ke dalam format bendera resmi: `academy{71m311n3_0u7113r_h3r_43a2e7af}`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{71m311n3_0u7113r_h3r_43a2e7af}`
- **Flag Komunitas:** `CTF{71m311n3_0u7113r_h3r_43a2e7af}`
- **Log Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 720,
    "flag": "academy{71m311n3_0u7113r_h3r_43a2e7af}",
    "correct": true,
    "historical": false
  }
  ```
  Status respons HTTP: `201 Created` mengonfirmasi token valid dan tercatat secara definitif.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Rekomendasi Remediasi & Hardening (Defensive Perspective):**
   - **Pemantauan Anomali Distribusi Timestamp:** Menerapkan skrip audit berkala untuk memindai berkas dengan timestamp di luar rentang wajar (misalnya berkas di masa depan atau sebelum tanggal deployment sistem).
   - **Audit Syscall Manipulasi Waktu:** Mengaktifkan subsistem `auditd` untuk memantau pemanggilan fungsi sistem `utimes`, `utimensat`, dan `settimeofday` oleh proses non-root atau proses yang tidak terdaftar dalam siklus pemeliharaan sah.
   - **Penerapan File Integrity Monitoring (FIM):** Menggunakan alat FIM (AIDE, Tripwire) dengan basis data tanda tangan kriptografis (SHA-256) sehingga perubahan berkas sistem di direktori biner `/bin` atau `/usr/bin` langsung memicu peringatan terlepas dari timestamp palsu yang diterapkan.

2. **Relevansi Modul LKS Cyber Security:**
   - **Digital Forensics Analysis:** Penguasaan teknik ekstraksi *bodyfile* dan pembedahan linimasa MAC adalah keterampilan dasar wajib dalam modul investigasi bukti digital LKS Cyber Security Nasional.
   - **Identifikasi Taktik Evasion / Anti-Forensics:** Memahami bahwa upaya penyembunyian yang ceroboh justru meninggalkan artefak unik yang mempercepat penemuan jejak insiden keamanan.
