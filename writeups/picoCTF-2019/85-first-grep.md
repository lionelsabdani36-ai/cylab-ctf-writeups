# Writeup: First Grep (Challenge ID: 85)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Regular Expression & Pattern Searching
- **Difficulty:** Easy (diff=1)
- **Author:** Alex Fulton
- **Event:** picoCTF 2019
- **Points:** 100
- **Flag:** `academy{grep_is_good_to_find_things_3FCACd2A}`

---

## Problem Statement & Scope

Diberikan sebuah berkas data teks bernama `file` berukuran ~14.5 KB yang dipenuhi oleh ribuan baris teks acak (garbage data). Deskripsi tantangan menyatakan:
> *"Can you find the flag in the file? This would be really tedious to look through manually, something tells me there is a better way. The flag is in this file."*

Tujuan pembelajaran dari modul ini adalah menguji kecakapan peserta dalam menyaring aliran data besar (*data filtering*), mengenali format token target, dan mengoperasikan utilitas pencarian pola reguler (*Regular Expressions*) standar POSIX (`grep`) tanpa harus membaca teks acak secara manual.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Standar POSIX Regex & Utilitas `grep` (Global Regular Expression Print):**
   - Utilitas `grep` membaca berkas teks per baris dan membandingkannya terhadap pola ekspresi reguler tertentu.
   - Algoritma pencarian `grep` (berbasis varian Boyer-Moore / DFA/NFA) berjalan dalam kompleksitas waktu linier $O(N)$ terhadap ukuran berkas, menjadikannya standar industri dalam investigasi *log analysis* dan respons insiden (NIST SP 800-86 / SP 800-115).
   - Melakukan pencarian manual (*eyeballing*) terhadap berkas berukuran besar tidak hanya membuang waktu tetapi juga rentan terhadap bias persepsi manusia (*human error*).

2. **Penyimpanan Informasi Sensitif dalam Teks Terbuka (CWE-312):**
   - Berkas target menyimpan token sensitif (*flag*) di antara blok teks acak tanpa adanya enkripsi atau proteksi struktural.
   - Karena token mempertahankan format awalan standar (`academy{...}` atau `picoCTF{...}`), pola tersebut dapat diekstraksi secara deterministik menggunakan satu ekspresi regex sederhana.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak Lab:**
   Unduh berkas artefak langsung dari CDN:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/5d7f4358263155557302dec0109cb10471df58afe72ce4507fc85ade2e3476c3/file
   ```

2. **Inspeksi Karakteristik Berkas:**
   ```bash
   wc -l file
   wc -c file
   ```
   Keluaran menunjukkan berkas berisi ratusan baris dengan total 14,546 karakter.

3. **Pencarian Pola Token Menggunakan `grep`:**
   Jalankan utilitas `grep` dengan mencocokkan pola awalan flag:
   ```bash
   grep -E "academy\{.*\}|picoCTF\{.*\}" file
   ```
   Atau cukup:
   ```bash
   grep "academy{" file
   ```
   Terminal seketika menampilkan baris berisi flag lengkap:
   ```text
   academy{grep_is_good_to_find_things_3FCACd2A}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{grep_is_good_to_find_things_3FCACd2A}`
- **Verifikasi API:** Validasi token pada endpoint `POST /api/submissions/` mengembalikan `{"correct": true, "challenge": 85}` (Status HTTP 201 Created).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kemampuan Log Carving & Forensik Teks (LKS Blue Team):** Dalam skenario lomba LKS Cyber Security, berkas log server web (misal access.log Apache/Nginx) atau audit log Linux (`/var/log/audit/audit.log`) kerap memuat puluhan ribu baris. Keahlian mengombinasikan `grep`, `awk`, dan `sed` adalah keterampilan wajib untuk mendeteksi jejak penyerang (*attack signatures*), injeksi SQL, dan webshell access.
- **Data Sanitization & Least Exposure (Defensive):** Data rahasia (token sesi, kunci privat, password) tidak boleh pernah dimasukkan ke dalam berkas log publik, repositori publik, atau artefak build aplikasi. Implementasikan filter logging otomatis (*masking/redaction*) untuk mencegah kebocoran data sensitif (OWASP Top 10 A02:2021 - Cryptographic Failures).

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_85_first_grep.py`.
