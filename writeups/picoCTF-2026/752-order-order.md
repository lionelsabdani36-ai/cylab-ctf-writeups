# Writeup: ORDER ORDER (Challenge ID: 752)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation
- **Difficulty:** Hard
- **Event:** picoCTF 2026
- **Points:** 300
- **Author:** Darkraicg492
- **Flag:** `academy{s3c0nd_0rd3r_1t_1s_4611c226}`

---

## Problem Statement & Scope
Peserta diberikan akses ke aplikasi web Expense Tracker interaktif yang menyediakan fitur otentikasi (registrasi dan login), pencatatan pengeluaran harian, serta pembuatan laporan pengeluaran terkompresi (Generate Report). Evaluasi keamanan menyeluruh terhadap input pengeluaran (Description, Amount, Date) tidak membuahkan celah injeksi langsung. Namun, mekanisme pembuatan laporan mengekstraksi data secara asinkron menggunakan identitas pengguna yang tersimpan sebelumnya di basis data, memunculkan vektor serangan Second-Order SQL Injection. Sasaran audit adalah mengeksploitasi keterlambatan eksekusi kueri ini untuk mengekstraksi skema basis data SQLite dan membaca flag rahasia yang disimpan pada tabel tersembunyi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Second-Order SQL Injection (CWE-89):**
   Second-Order SQL Injection terjadi ketika input berbahaya dari pengguna disimpan terlebih dahulu ke dalam sistem penyimpanan data persisten (seperti tabel pengguna saat proses registrasi) tanpa mengeksekusinya secara langsung, lalu di kemudian hari diambil dan dimasukkan ke dalam kueri SQL baru tanpa parameterisasi. Pada aplikasi ini, endpoint registrasi menyimpan nama pengguna (`username`) secara aman atau menggunakan kueri terparameterisasi, tetapi rutin pembuatan laporan mengeksekusi kueri gabungan string mentah:
   ```sql
   SELECT id, amount, category FROM expenses WHERE username = '<stored_username>';
   ```
2. **Kelemahan Penentuan Jumlah Kolom via ORDER BY:**
   Klausul `ORDER BY N` pada SQL digunakan penyerang untuk memetakan jumlah kolom yang diproyeksikan oleh kueri asli. Jika angka indeks kolom $N$ melebihi jumlah kolom hasil kueri, mesin SQL (seperti SQLite) memicu kesalahan sintaksis operasional (`OperationalError: 1st ORDER BY term out of range`), memberikan sinyal biner (*boolean oracle*) atas struktur tabel.
3. **NIST SP 800-115 Section 4.3 & OWASP Top 10 A03:2021 (Injection):**
   Standar evaluasi keamanan perangkat lunak NIST SP 800-115 mensyaratkan peninjauan mendalam terhadap aliran data sekunder (*secondary data flows*). Data yang berasal dari basis data internal tidak boleh diperlakukan sebagai data tepercaya (*trusted data*) ketika dirangkai kembali ke dalam instruksi interpreter atau kueri hilir.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Identifikasi Titik Eksekusi Sekunder:**
   - Formulir input pengeluaran dan login menerapkan prepared statements.
   - Pembuatan akun baru dengan payload tanda petik tunggal (`dum'`) pada field `username` berhasil terdaftar tanpa galat.
   - Ketika masuk ke dashboard akun tersebut dan menekan tombol **GENERATE REPORT**, sistem mengembalikan status kegagalan pembuatan laporan pada kotak masuk, membuktikan adanya syntax error pada eksekusi kueri laporan di sisi backend.

2. **Enumerasi Jumlah Kolom Kueri Asli (ORDER BY Probing):**
   Daftarkan akun uji coba dengan payload penentuan kolom pada parameter `username`:
   - Akun 1: `' ORDER BY 1--` -> Laporan sukses terbuat.
   - Akun 2: `' ORDER BY 2--` -> Laporan sukses terbuat.
   - Akun 3: `' ORDER BY 3--` -> Laporan sukses terbuat.
   - Akun 4: `' ORDER BY 4--` -> Pembuatan laporan gagal (*error*).
   Disimpulkan bahwa kueri `SELECT` pada fungsi laporan memproyeksikan tepat 3 kolom data.

3. **Enumerasi Skema Tabel SQLite (`sqlite_master`):**
   Daftarkan akun baru dengan payload `UNION SELECT` yang menargetkan tabel metadata bawaan SQLite:
   ```text
   ' UNION SELECT name, NULL, NULL FROM sqlite_master WHERE type='table'--
   ```
   Setelah menekan **GENERATE REPORT**, unduh berkas CSV laporan yang dihasilkan. Struktur tabel internal terungkap pada baris data laporan:
   - `users`
   - `expenses`
   - `aDNyM19uMF9mMTRn`
   Nama tabel `aDNyM19uMF9mMTRn` merupakan representasi Base64 dari string `h3r3_n0_f14g`.

4. **Ekstraksi Konten Flag dari Tabel Target:**
   Daftarkan akun terakhir dengan payload ekstraksi seluruh data dari tabel tersembunyi:
   ```text
   ' UNION SELECT flag, secret_note, NULL FROM aDNyM19uMF9mMTRn--
   ```
   Tekan **GENERATE REPORT** dan unduh berkas CSV dari kotak masuk pengguna. Berkas memuat nilai flag:
   `picoCTF{s3c0nd_0rd3r_1t_1s_4611c226}`.
   Dikonversikan ke format resmi CyLab Security Academy: `academy{s3c0nd_0rd3r_1t_1s_4611c226}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{s3c0nd_0rd3r_1t_1s_4611c226}`
- **Native PicoCTF Flag:** `picoCTF{s3c0nd_0rd3r_1t_1s_4611c226}`
- **Status Solver:** Terverifikasi melalui simulasi otomasi `scripts/solve_752_order_order.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Prepared Statements Menyeluruh (Parameterized Queries di Semua Layer):**
  Jangan pernah memperlakukan data yang ditarik dari basis data sebagai data aman. Setiap kueri lanjutan wajib menggunakan prepared statements dengan parameter binding (`SELECT ... WHERE username = ?`), bukan konkatenasi string format `f"..."` atau `sprintf`.
- **Validasi Karakter Input pada Lapisan Registrasi (Input Sanitization):**
  Terapkan whitelist regex pada username saat pendaftaran (`^[a-zA-Z0-9_]{3,30}$`). Menolak tanda petik (`'`), strip ganda (`--`), dan karakter khusus lainnya sejak awal akan memangkas seluruh potensi second-order injection.
- **Penerapan Hak Akses Minimum Basis Data (Database Least Privilege):**
  Pisahkan pengguna basis data aplikasi web ke dalam skema terbatas, dan pastikan tabel sensitif atau metadata administratif tidak dapat diakses melalui kueri umum pelaporan.