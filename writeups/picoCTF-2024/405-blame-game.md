# Writeup: Blame Game (Challenge ID: 405)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Git Forensic & Metadata Analysis
- **Difficulty:** Easy
- **Author:** Jeffery John
- **Event:** picoCTF 2024
- **Points:** 75
- **Flag:** `academy{@sk_th3_1nt3rn_8bd9c746}`

---

## Problem Statement & Scope
Diberikan sebuah arsip zip repositori Git (`challenge.zip`) yang memuat direktori `drop-in`. Program Python di dalamnya mengalami kerusakan sintaks yang menyebabkan program gagal berjalan. Peserta diminta menyelidiki riwayat komit version control untuk mencari pelaku kerusakan tersebut beserta flag yang ditinggalkan.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Keabadian Riwayat Version Control (Git History Immutability):** Sistem kendali versi Git menyimpan riwayat commit dan objek pohon secara permanen di direktori `.git/objects`. Komit yang merusak atau memperkenalkan celah keamanan tetap tersimpan dalam riwayat commit meskipun file kerja telah diubah atau diperbaiki pada commit berikutnya.
2. **Metadata Atribusi Commit (Author & Committer Info):** Setiap objek commit Git menyimpan nama pengarang (*author name*), email pengarang, timestamp, dan pesan komit. Bidang author name dapat dimanipulasi untuk menyimpan string arbitrer, termasuk token rahasia atau payload investigasi forensik.
3. **Pemanfaatan Utilitas `git blame` dan `git log`:** Perintah `git blame` mengatribusikan setiap baris kode kepada commit dan author spesifik, sementara `git log` menelusuri seluruh riwayat perubahan metadata.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Ekstraksi arsip repositori:
   ```bash
   unzip challenge.zip
   cd drop-in
   ```
2. Analisis berkas `message.py`:
   ```bash
   python3 message.py
   # SyntaxError: '(' was never closed
   ```
3. Lakukan penelusuran `git blame` pada berkas `message.py` untuk mengidentifikasi commit yang mengubah baris kode tersebut:
   ```bash
   git blame message.py
   # d621b1a3 (academy{@sk_th3_1nt3rn_8bd9c746} 2026-09-23 05:07:00 +0000 1) print("Hello, World!"
   ```
4. Atau lakukan pencarian komit yang menyertakan pola flag pada nama pembuat (*author*):
   ```bash
   git log --all --format="%an" | grep "academy{"
   # Output: academy{@sk_th3_1nt3rn_8bd9c746}
   ```
5. Periksa detail commit `d621b1a352d14b62e3ec51e8d0bc91ba14b44eae`:
   ```bash
   git show d621b1a352d14b62e3ec51e8d0bc91ba14b44eae
   # Author: academy{@sk_th3_1nt3rn_8bd9c746} <ops@cylabacademy.org>
   # Message: optimize file size of prod code
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{@sk_th3_1nt3rn_8bd9c746}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Audit Repositori Git Publik:** Sebelum mempublikasikan repositori kode ke publik (GitHub/GitLab), pastikan tidak ada data sensitif, kunci API, atau kredensial yang pernah ter-commit di masa lalu.
- **Pembersihan Riwayat Komit (Git History Scrubbing):** Jika rahasia secara tidak sengaja ter-commit, modifikasi commit biasa tidak cukup. Wajib gunakan alat seperti `git-filter-repo` atau BFG Repo-Cleaner untuk menghapus objek rahasia dari seluruh riwayat `.git/` secara permanen, lalu lakukan rotasi kredensial segera.
