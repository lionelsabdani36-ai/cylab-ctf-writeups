# Writeup: Big Zip (Challenge ID: 322)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Recursive Directory Traversal & Pattern Matching
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{gr3p_15_m4g1c_ef8790dc}`

---

## Problem Statement & Scope

Diberikan sebuah berkas arsip terkompresi berukuran relatif besar bernama `big-zip-files.zip`. Arsip tersebut memuat hierarki folder bercabang yang sangat dalam dengan ribuan subdirektori acak serta berkas teks dummy di dalamnya.

Peserta ditugaskan untuk mengekstrak arsip dan mencari letak flag tersembunyi yang tersimpan di salah satu berkas teks tanpa melakukan penelusuran manual satu per satu.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kompleksitas Penelusuran Hierarki Berkas (Filesystem Hierarchy Traversal):**
   - Struktur direktori bercabang acak dengan ratusan sub-folder dirancang untuk menggagalkan inspeksi visual manual.
   - Pada investigasi forensik digital atau audit keamanan sistem, analis sering berhadapan dengan direktori log atau backup masif berukuran puluhan gigabyte.
2. **Pola Pencarian Berulang Berbasis Utilitas POSIX (`grep` Recursive):**
   - Utilitas `grep` menyediakan flag `-r` atau `-R` (*recursive*) yang secara rekursif menelusuri setiap file di bawah direktori target, membuka konten, dan mencocokkan string dengan pola regular expression.
   - Opsi penting:
     - `-r` / `-R`: Menelusuri seluruh subdirektori secara rekursif.
     - `-n`: Menampilkan nomor baris tempat kecocokan ditemukan.
     - `-i`: Pencarian *case-insensitive*.
     - `-I`: Mengabaikan berkas biner secara otomatis.
   - Kompleksitas waktu pencarian adalah linear $O(N)$ terhadap total ukuran byte seluruh berkas, sehingga ribuan berkas teks dapat dipindai dalam hitungan detik.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh berkas arsip `big-zip-files.zip` dari server pustaka berkas CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/b150f6f4d21f46fc2bba57ef49c7305541fa8e9bfa4241dfe8d066b99de56200/big-zip-files.zip
   ```
2. Ekstrak arsip ke direktori kerja sementara:
   ```bash
   unzip -q big-zip-files.zip -d big_zip_extracted/
   ```
3. Jalankan pencarian rekursif untuk pola token flag `academy{` atau `picoCTF{`:
   ```bash
   grep -rn "academy{" big_zip_extracted/
   ```
   Atau jika mencari format umum picoCTF:
   ```bash
   grep -rn "picoCTF{" big_zip_extracted/
   ```
4. Output langsung menampilkan file spesifik dan nomor baris:
   ```text
   big_zip_extracted/big-zip-files/folder_pmbymkjcya/folder_cawigcwvgv/folder_ltdayfmktr/folder_fnpfclfyee/whzxrpivpqld.txt:1:information on the record will last a billion years. Genes and brains and books encode academy{gr3p_15_m4g1c_ef8790dc}
   ```
5. Ekstraksi token flag:
   `academy{gr3p_15_m4g1c_ef8790dc}`
6. Jalankan skrip reproduksi mandiri `scripts/solve_322_big_zip.py` untuk validasi otomatis.

---

## Flag & Verifikasi

- **Flag:** `academy{gr3p_15_m4g1c_ef8790dc}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 322, "flag": "academy{gr3p_15_m4g1c_ef8790dc}", "correct": true}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemahiran navigasi CLI Linux, ekstraksi arsip massal, dan teknik *text stream mining* berbasis regular expression.
  - Efisiensi waktu penyelesaian tantangan kompetisi: menghindari inspeksi antarmuka grafis (GUI file manager) yang lambat ketika berhadapan dengan ribuan berkas.
- **Mitigasi Defensif:**
  - **Pencegahan Kebocoran Kredensial pada Log dan Kode (Secret Hygiene):**
    Pengembang sering kali tanpa sengaja meninggalkan token rahasia, kunci privat, atau password di berkas sementara dalam repositori besar.
  - **Terapkan Pre-Commit Secret Scanning Hooks:**
    Pasang alat otomatis seperti Gitleaks atau Trufflehog pada alur kerja CI/CD untuk memindai seluruh pohon direktori dan riwayat commit secara rekursif sebelum kode diunggah ke repositori publik.
