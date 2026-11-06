# Writeup: Sql Map1 (Challenge ID: 729)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Database Security
- **Difficulty:** Medium (diff=2)
- **Event:** picoCTF 2026
- **Flag:** `academy{sqlm4p_md5_cr4ck_d00rw4y_729}`

---

## Problem Statement & Scope

Tantangan ini menyajikan aplikasi web portal pencarian pengguna:
> *"You’ve been hired by a shadowy group of pentesters who love a good puzzle. The system looks ordinary, but appearances lie. Somewhere inside, sloppy code and legacy hashing practices left a tiny, perfect doorway for an attacker. Your mission — should you choose to accept it — is to slip through that doorway, act as a legit user and retrieve the secret flag."*
> 
> Petunjuk:
> 1. *"Search box looks interesting."*
> 2. *"Passwords should not be stored in md5 format."*
> 3. *"CrackStation is a great online tool for cracking hashes."*
> 4. *"Sample SqlMap command: `sqlmap -u <URL_for_search> --cookie=\"PHPSESSID=1111111111111\" -p <vulnerable_parameter> --batch --tables`"*

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **SQL Injection pada Parameter Pencarian (CWE-89):**
   Aplikasi menggabungkan input pengguna secara langsung ke dalam kueri basis data SQL tanpa menggunakan *parameterized queries* (Prepared Statements). Penyerang dapat menyuntikkan operator logika SQL (seperti `' OR 1=1 --`) atau kueri `UNION SELECT` untuk mengekstrak skema tabel dan data dari basis data.
2. **Insecure Password Storage via Deprecated MD5 Hash (CWE-328):**
   Tabel pengguna menyimpan kata sandi menggunakan fungsi hash MD5 tanpa *salt* kriptografis unik. MD5 memiliki entropi rendah terhadap serangan *rainbow table* dan *pre-computed dictionary*, sehingga hash dapat dipecahkan dalam hitungan detik menggunakan layanan basis data hash publik (seperti CrackStation) atau kamus kata sandi standar (seperti `rockyou.txt`).
3. **Broken Authentication / Credential Exposure:**
   Setelah kata sandi admin atau akun berhak istimewa berhasil didekripsi dari hash MD5, penyerang dapat melakukan login resmi ke panel portal untuk mengakses flag.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Enumerasi Titik Masuk (Reconnaissance):**
   Mengidentifikasi form pencarian yang mengirimkan parameter HTTP GET/POST ke backend aplikasi.
2. **Uji Injeksi Manual:**
   Mengirimkan tanda petik tunggal `'` dan memeriksa apakah aplikasi menghasilkan pesan kesalahan basis data atau anomali respon HTTP.
3. **Ekstraksi Skema & Tabel (Automated / Manual SQLi):**
   Menjalankan enumerasi basis data untuk mengekstrak tabel kredensial pengguna:
   ```bash
   sqlmap -u "http://target/search.php?query=test" --batch --dump -T users
   ```
   Ditemukan baris akun pengguna yang memuat username dan hash kata sandi MD5 32 karakter heksadesimal.
4. **Penebakan Hash Kata Sandi (Hash Cracking):**
   Mencocokkan hash MD5 target pada kamus kata sandi atau layanan CrackStation untuk memperoleh teks asli (*plaintext password*).
5. **Otentikasi & Pengambilan Flag:**
   Masuk ke halaman login menggunakan kredensial yang telah dipulihkan untuk menampilkan flag rahasia.

---

## Flag & Verifikasi

- **Flag:** `academy{sqlm4p_md5_cr4ck_d00rw4y_729}`
- **Validasi Platform:** Solved on CyLab Academy.

---

## Remediasi & Mitigasi (Perspektif Defensive LKS)

1. **Terapkan Prepared Statements (Parameterized Queries):**
   Selalu gunakan antarmuka kueri berparameter (seperti PDO di PHP, PreparedStatement di Java, atau parameterized query di Go/Node.js) untuk memisahkan kode SQL dari data input pengguna.
2. **Tinggalkan Algoritma Hash Usang (MD5 / SHA-1):**
   Jangan pernah menyimpan kata sandi menggunakan MD5 atau SHA-1. Gunakan algoritma hashing kata sandi yang lambat dan *memory-hard* yang dirancang khusus untuk resistensi GPU/ASIC, seperti **Argon2id**, **bcrypt**, atau **PBKDF2** dengan *work factor* yang memadai dan *salt* unik per pengguna.
3. **Audit Otomatisasi CI/CD:**
   Integrasikan pemindai kode statis (SAST) seperti Semgrep atau SonarQube ke dalam pipeline repositori untuk mendeteksi kueri SQL dinamis sebelum dideploy ke lingkungan produksi.
