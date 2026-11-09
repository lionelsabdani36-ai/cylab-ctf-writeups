# Writeup: Timeline 1 (Challenge ID: 721)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / MACB Temporal Incident Reconstruction & Anti-Forensics Analysis
- **Difficulty:** Hard (3)
- **Points:** 400
- **Author:** picoCTF
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{573417h13r_7h4n_7h3_1457_58527bb222}`
- **Flag Komunitas:** `CTF{573417h13r_7h4n_7h3_1457_58527bb222}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), ISO/IEC 27037 (Guidelines for Digital Evidence Handling), CWE-506 (Embedded Malicious Code), & SleuthKit File System Forensic Analysis Framework.

---

## Problem Statement & Scope

Pada modul bimbingan teknis tingkat lanjut `Timeline 1`, peserta diuji dalam metodologi investigasi digital forensics berbasis rekaman linimasa metadata sistem berkas (*filesystem timeline analysis*):
- Skenario lingkungan: Disediakan salinan partisi sistem operasi Linux berbasis ext4 terkompresi: `timeline-1-partition4.img.gz` (~490 MB).
- Pernyataan tantangan:
  > *"Can you find the flag in this disk image? Wrap what you find in the academy{} flag format."*
- Petunjuk resmi investigasi:
  1. *"Create a Sleuthkit MAC timeline!"*
  2. *"Look at recent timestamps"*
  3. *"Pay close attention to timestamps near an anti-forensic action"*
  4. *"Filter only new files by grepping for `macb`"*
- Sasaran pengujian: Mengekstrak metadata inode sistem berkas ext4 menggunakan SleuthKit (`fls` & `mactime`), menyaring rekaman linimasa berdasarkan atribut temporal `macb`, mendeteksi aktivitas anti-forensik (*log wiping / history clearing*), mengekstrak artefak persisten tersembunyi via `icat`, mendekode muatan rahasia, serta memvalidasi token resmi pada endpoint REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Metadata Waktu Inode ext4 & Atribut MACB:**
   Sistem berkas modern Linux (ext4) mencatat empat penanda waktu utama untuk setiap inode berkas:
   - **M (Modified Time):** Waktu saat isi data berkas terakhir kali dimodifikasi.
   - **A (Accessed Time):** Waktu saat berkas terakhir kali dibaca atau diakses.
   - **C (Changed/Status Time):** Waktu saat metadata inode (izin akses, kepemilikan, tautan) diubah.
   - **B (Birth/Creation Time):** Waktu pembuatan berkas pertama kali (*file creation time*).
   Ketika utilitas SleuthKit `mactime` memproses data *bodyfile*, rekaman diwakili oleh urutan 4 karakter: `macb`. Jika berkas baru saja dibuat dan belum pernah dimodifikasi atau dibaca kembali sesudahnya, keempat timestamp tersebut bernilai identik, sehingga ditandai dengan flag huruf penuh: `macb`.
   Grepping terhadap `macb` secara efektif memfilter berkas-berkas yang baru saja dijatuhkan (*freshly dropped payloads*) dari kebisingan ribuan berkas sistem lama.

2. **Deteksi Aksi Anti-Forensik (Anti-Forensics Triage):**
   Pelaku penyerangan seringkali berusaha menghapus jejak eksekusi dengan membersihkan riwayat shell (`.bash_history` atau `.ash_history`). Namun, tindakan pembersihan itu sendiri meninggalkan jejak forensik:
   - Riwayat shell yang hanya menyisakan satu perintah (misalnya perintah `poweroff`) mengindikasikan upaya sanitasi manual yang disengaja.
   - Timestamp modifikasi pada riwayat shell tersebut memberikan jangkar waktu kritis (*critical incident temporal anchor*). Aktivitas berkas yang terjadi tepat beberapa detik sebelum perintah `poweroff` dijalankan merupakan target prioritas investigasi penyerangan.

3. **Infiltrasi & Persistensi Terselubung (CWE-506):**
   Pelaku memanfaatkan direktori konfigurasi standar `/etc/` untuk menyembunyikan berkas data non-standar (`/etc/chat`) yang berisi token terenkripsi/Base64. Karena sistem langsung dimatikan setelah pembuatan berkas tersebut, atribut `macb` pada inode `/etc/chat` tetap utuh dan sinkron pada tanggal 1 Desember 2025 pukul 21:50:07 UTC.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Dekompresi & Rekonstruksi Image Partisi:**
   Mendekompresi artefak image disk:
   ```bash
   gzip -dc timeline-1-partition4.img.gz > p721.img
   ```

2. **Pembangkitan Linimasa MAC SleuthKit:**
   Mengekstrak rekaman *bodyfile* dari filesystem ext4 dan mengonversinya menjadi linimasa waktu terurut:
   ```bash
   fls -r -m / -o 0 p721.img | mactime -d -b - > timeline.csv
   ```

3. **Penyaringan Anomali `macb` & Analisis Anti-Forensik:**
   Menyaring baris yang memuat penanda `macb`:
   ```bash
   grep ",macb," timeline.csv | tail -n 10
   ```
   Ditemukan korelasi aktivitas penyerang pada rentang waktu 21:42 - 21:50 UTC:
   - `21:42:10`: Modifikasi direktori manajer paket `/var/cache/apk`.
   - `21:45:33`: Eksekusi/instalasi utilitas jaringan `/usr/bin/curl`.
   - `21:50:07`: Pembuatan berkas tersembunyi `/etc/chat` (inode `32716`, ukuran 48 byte).
   - `21:50:18`: Pembersihan riwayat shell `/root/.ash_history` (inode `4943`, isi perintah tunggal `poweroff`).

4. **Ekstraksi Berkas Menggunakan SleuthKit `icat`:**
   Membaca langsung blok data inode 32716 dari image disk tanpa me-mount sistem berkas:
   ```bash
   icat -o 0 p721.img 32716
   ```
   Diperoleh muatan ber-encoding Base64:
   `NTczNDE3aDEzcl83aDRuXzdoM18xNDU3XzU4NTI3YmIyMjIK`.

5. **Decoding Muatan & Rekonstruksi Flag:**
   Mendekode string Base64:
   ```bash
   echo "NTczNDE3aDEzcl83aDRuXzdoM18xNDU3XzU4NTI3YmIyMjIK" | base64 -d
   ```
   Hasil dekode: `573417h13r_7h4n_7h3_1457_58527bb222`.
   Membungkus hasil ke dalam format bendera resmi: `academy{573417h13r_7h4n_7h3_1457_58527bb222}`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{573417h13r_7h4n_7h3_1457_58527bb222}`
- **Flag Komunitas:** `CTF{573417h13r_7h4n_7h3_1457_58527bb222}`
- **Log Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 721,
    "flag": "academy{573417h13r_7h4n_7h3_1457_58527bb222}",
    "correct": true,
    "historical": false
  }
  ```
  Status respons HTTP: `201 Created` mengonfirmasi token valid dan tercatat secara definitif.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Rekomendasi Remediasi & Hardening (Defensive Perspective):**
   - **Sentralisasi Log Sistem (Remote SIEM):** Tindakan anti-forensik lokal (seperti `history -c`, penghapusan berkas log, atau `poweroff`) menjadi sia-sia jika sistem meneruskan log otentikasi dan audit (*auditd*, *syslog*) ke server penampung log terpusat (*append-only remote logging*) secara real-time.
   - **Pemantauan Integritas Berkas (File Integrity Monitoring / FIM):** Menerapkan alat FIM (seperti OSSEC, Wazuh, atau Tripwire) untuk mendeteksi penambahan berkas baru atau perubahan metadata pada direktori sistem sensitif (`/etc`, `/bin`, `/sbin`).
   - **Proteksi Imutabilitas Riwayat Perintah:** Mengonfigurasi variabel shell lingkungan `PROMPT_COMMAND='history -a'` dan menetapkan atribut `chattr +a .bash_history` (hanya append) untuk mencegah manipulasi riwayat eksekusi oleh pengguna lokal.

2. **Relevansi Modul LKS Cyber Security:**
   - **Digital Forensics & Incident Response (DFIR):** Analisis linimasa temporal menggunakan SleuthKit (`fls`, `mactime`, `icat`) adalah materi inti pada modul investigasi forensik disk LKS Cyber Security Nasional.
   - **Anti-Forensic Triage:** Kemampuan membedakan anomali timestamp buatan (*timestomping*) dengan berkas baru bertanda `macb` yang lolos dari pembersihan jejak penyerang merupakan keterampilan krusial dalam rekonstruksi insiden keamanan siber.
