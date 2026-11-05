# Writeup: First Find (Challenge ID: 320)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Filesystem Search & Hierarchy Navigation
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{f1nd_15_f457_ab443fd1}`

---

## Problem Statement & Scope

Diberikan sebuah berkas arsip biner ZIP bernama `files.zip`. Di dalam arsip tersebut terdapat berkas rahasia bernama `uber-secret.txt` yang tersimpan pada subdirektori tersembunyi.

Peserta ditugaskan untuk mengekstrak arsip, menemukan berkas target secara efisien menggunakan utilitas pencarian berkas POSIX, dan mengekstrak token bendera resmi format `academy{...}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Konvensi Direktori dan Berkas Tersembunyi (Hidden Dotfiles) pada Linux:**
   - Dalam lingkungan sistem operasi berbasis POSIX/Linux, berkas atau direktori yang diawali dengan karakter titik (`.`) dianggap sebagai entitas tersembunyi.
   - Perintah standar `ls` secara default menyembunyikan berkas titik ini kecuali diberikan flag `-a` (*all*).
   - Pengembang atau pelaku ancaman (*threat actors*) kerap memanfaatkan direktori bertitik (seperti `.secret/` atau `.hidden/`) untuk menyembunyikan artefak mencurigakan dari inspeksi berkala pengguna awam.
2. **Pencarian Pohon Direktori Menggunakan `find`:**
   - Perintah `find` melakukan penelusuran struktur hierarki direktori sistem (*directory tree traversal*) secara rekursif.
   - Berbeda dari `ls`, `find` secara default memeriksa seluruh simpul direktori termasuk berkas bertitik tanpa memerlukan flag khusus.
   - Sintaks `find <path> -name "<pattern>"` membandingkan nama berkas di setiap simpul secara efisien.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh berkas `files.zip` dari repositori pustaka CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/72ca8cb60e55a597886dfb8e20bdb28d3ea7e73ca72987eb813a3558a8dd22bf/files.zip
   ```
2. Ekstrak arsip:
   ```bash
   unzip -q files.zip -d files_extracted/
   ```
3. Lakukan pencarian file `uber-secret.txt` di dalam folder hasil ekstraksi:
   ```bash
   find files_extracted/ -name "uber-secret.txt"
   ```
   Hasil pencarian mengembalikan jalur lengkap berkas:
   ```text
   files_extracted/files/adequate_books/more_books/.secret/deeper_secrets/deepest_secrets/uber-secret.txt
   ```
   Perhatikan bahwa berkas berada di dalam folder tersembunyi `.secret/`.
4. Baca isi berkas menggunakan `cat`:
   ```bash
   cat files_extracted/files/adequate_books/more_books/.secret/deeper_secrets/deepest_secrets/uber-secret.txt
   ```
   Output:
   ```text
   academy{f1nd_15_f457_ab443fd1}
   ```
5. Jalankan skrip reproduksi mandiri `scripts/solve_320_first_find.py` untuk validasi otomatis.

---

## Flag & Verifikasi

- **Flag:** `academy{f1nd_15_f457_ab443fd1}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 320, "flag": "academy{f1nd_15_f457_ab443fd1}", "correct": true}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemahiran navigasi sistem berkas Linux untuk modul *Forensics & Incident Response*.
  - Mengetahui cara menemukan artefak tersembunyi (*hidden files / dot directories*) yang sering digunakan malware atau webshell untuk mengelabui administrator server.
- **Mitigasi Defensif:**
  - **Audit Berkas dan Direktori Bertitik Secara Berkala:**
    Sistem monitoring integritas berkas (seperti OSSEC atau Wazuh FIM) harus dikonfigurasi untuk memicu peringatan (*alert*) bila terdapat direktori baru yang diawali titik pada lokasi publik seperti `/tmp`, `/dev/shm`, atau web root `/var/www/html/`.
  - **Audit Hak Akses Berkas:**
    Pastikan direktori aplikasi tidak memiliki izin tulis terbuka (*world-writable*) yang memungkinkan pengguna tanpa izin membuat struktur folder tersembunyi.
