# Writeup: hashcrack (Challenge ID: 475)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Fast Hash Function Identification & Multi-Stage Dictionary Cracking
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** Nana Ama Atombo-Sackey
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}`
- **Flag Platform Asli:** `picoCTF{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}`
- **Flag Komunitas:** `CTF{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Cryptographic Assessment & Credential Auditing), FIPS 180-4 (Secure Hash Standard), RFC 1321 (The MD5 Message-Digest Algorithm), CWE-328 (Use of Weak Hash), CWE-759 (Use of a One-Way Hash without a Salt), & CWE-916 (Use of Password Hash With Insufficient Computational Effort).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Cryptography & Credential Auditing*:
- **Skenario Tantangan:** Sebuah server perusahaan mengalami insiden pelanggaran data (*data breach*) akibat administrator sistem menggunakan algoritma hashing kata sandi yang lemah tanpa garam (*unsalted fast hashes*). Layanan autentikasi menantang penguji untuk memecahkan tiga tingkat hash berurutan (MD5, SHA-1, dan SHA-256) untuk membuktikan kelemahan proteksi kredensial dan memperoleh token rahasia.
- **Deskripsi Soal:** *"A company stored a secret message on a server which got breached due to the admin using weakly hashed passwords. Can you gain access to the secret stored within the server? Hints: 1. Understanding hashes is very crucial. Read more here, 2. Can you identify the hash algorithm? Look carefully at the length and structure of each hash identified, 3. Tried using any hash cracking tools?"*
- **Batasan Lingkungan & Scope Audit:**
  1. Identifikasi struktur digest heksadesimal berdasarkan representasi bit dan panjang karakter (32 hex = 128-bit, 40 hex = 160-bit, 64 hex = 256-bit).
  2. Dekonstruksi kelemahan fungsi hash kriptografi tujuan umum (*general-purpose hash*) ketika digunakan sebagai mekanisme penyimpanan kata sandi tanpa salt dan fungsi peregang kunci (*key-stretching*).
  3. Pemanfaatan kamus kata sandi standar industri (*rockyou.txt*) dan pembuatan tabel pencarian lokal (*precomputed hash dictionary*) berbobot waktu $O(1)$.
  4. Otomasi interaksi soket TCP netcat untuk menjawab tiga tahapan autentikasi berturut-turut dalam batas waktu timeout sesi.
  5. Verifikasi token resmi melalui REST API CyLab `POST /api/submissions/` (HTTP Status 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Identifikasi Fungsi Hash Berdasarkan Panjang Karakter Heksadesimal:**
   Fungsi hash kriptografis menghasilkan intisari (*digest*) dengan ukuran tetap tanpa memandang panjang masukan:
   - **MD5 (RFC 1321):** Ukuran keluaran 128 bit = 16 byte $\rightarrow$ direpresentasikan sebagai 32 karakter heksadesimal.
   - **SHA-1 (FIPS 180-4 / RFC 3174):** Ukuran keluaran 160 bit = 20 byte $\rightarrow$ direpresentasikan sebagai 40 karakter heksadesimal.
   - **SHA-256 (FIPS 180-4 / RFC 6234):** Ukuran keluaran 256 bit = 32 byte $\rightarrow$ direpresentasikan sebagai 64 karakter heksadesimal.

2. **Kelemahan Fast Hash Function untuk Penyimpanan Kredensial (CWE-328 / CWE-916):**
   Algoritma MD5, SHA-1, dan SHA-256 dirancang untuk integritas berkas dan efisiensi throughput komputasi tinggi. Perangkat keras modern (GPU cluster / ASIC) mampu menghitung puluhan miliar hash per detik. Ketika kata sandi di-hash tanpa parameter *work factor* yang dapat ditingkatkan (*tunable cost factor*), penyerang dapat melakukan serangan kamus (*dictionary attack*) atau serangan brute-force secara masif.

3. **Penyimpanan Hash Tanpa Garam (CWE-759):**
   Tanpa penambahan nilai acak unik (*salt*) per pengguna:
   $$\text{Digest} = H(\text{password})$$
   Dua pengguna dengan kata sandi yang sama akan memiliki digest identik. Kondisi ini memungkinkan penyerang menggunakan tabel prainisialisasi (*rainbow tables*) atau kamus hash global untuk membalikkan intisari kembali ke teks asli (*pre-image recovery*) dalam hitungan milidetik.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Koneksi ke Layanan Soket TCP:**
   Membuka koneksi netcat ke container target:
   ```bash
   nc chatelaine.cylabacademy.net 42998
   ```

2. **Tahap 1 — MD5 Hash Resolution:**
   - Hash yang diterima: `482c811da5d5b4bc6d497ffa98491e38` (32 karakter hex).
   - Identifikasi algoritma: MD5 (128-bit).
   - Pencocokan kamus:
     ```python
     import hashlib
     assert hashlib.md5(b"password123").hexdigest() == "482c811da5d5b4bc6d497ffa98491e38"
     ```
   - Input yang dikirimkan: `password123`.

3. **Tahap 2 — SHA-1 Hash Resolution:**
   - Hash yang diterima: `b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3` (40 karakter hex).
   - Identifikasi algoritma: SHA-1 (160-bit).
   - Pencocokan kamus:
     ```python
     assert hashlib.sha1(b"letmein").hexdigest() == "b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3"
     ```
   - Input yang dikirimkan: `letmein`.

4. **Tahap 3 — SHA-256 Hash Resolution:**
   - Hash yang diterima: `916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745` (64 karakter hex).
   - Identifikasi algoritma: SHA-256 (256-bit).
   - Pencocokan kamus:
     ```python
     assert hashlib.sha256(b"qwerty098").hexdigest() == "916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745"
     ```
   - Input yang dikirimkan: `qwerty098`.

5. **Penerimaan Flag & Eksekusi Solver Mandiri:**
   Server mengirimkan token bendera setelah ketiga tahap diverifikasi:
   ```bash
   python3 scripts/solve_475_hashcrack.py chatelaine.cylabacademy.net:42998
   ```
   Output eksekusi:
   ```text
   [+] Invarian identifikasi fungsi hash & kamus kamus kata sandi terverifikasi matematis (100% roundtrip)
   [*] Menghubungi target netcat: chatelaine.cylabacademy.net:42998...
   [+] Flag berhasil diekstraksi dari soket TCP: academy{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}
   [SUCCESS] Challenge 475 (hashcrack) verified: academy{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}`
- **Flag Platform Asli:** `picoCTF{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}`
- **Flag Komunitas:** `CTF{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}`
- **Verifikasi Submisi REST API:** POST `/api/submissions/` dengan payload `{"challenge": 475, "flag": "academy{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}"}` menghasilkan status HTTP 201 dengan atribut `correct: true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Adopsi Fungsi Hash Password Khusus (Password Hashing Functions / PHF):**
   Jangan pernah menggunakan *fast cryptographic hash* (MD5, SHA-1, SHA-256, SHA-512) secara langsung untuk menyimpan kata sandi. Wajib mengimplementasikan algoritma hashing berstandar modern seperti:
   - **Argon2id (RFC 9106 / Pemenang Password Hashing Competition):** Direkomendasikan oleh OWASP karena memiliki proteksi terhadap serangan berbasis GPU dan ASIC dengan parameter memori, waktu (*time cost*), dan paralelisme.
   - **bcrypt / scrypt / PBKDF2:** Sebagai standar industri yang teruji dengan pengaturan *work factor* yang dapat ditingkatkan secara berkala.

2. **Pemberian Salt Kriptografis Unik & Otomatis (CWE-759 Mitigation):**
   Setiap kata sandi wajib digabungkan dengan salt kriptografis unik berukuran minimal 16 byte (128 bit) yang dihasilkan melalui generator bilangan acak semu kriptografis (*CSPRNG* seperti `os.urandom()` atau `secrets`). Salt memastikan digest yang dihasilkan unik untuk setiap entri kredensial dan meniadakan serangan tabel pelangi (*rainbow tables*).

3. **Penegakan Kebijakan Kompleksitas Kata Sandi (NIST SP 800-63B):**
   Menerapkan filter daftar hitam kata sandi bocor (*breached password blacklist*) saat pendaftaran akun untuk mencegah pengguna memilih kata sandi umum seperti `password123`, `letmein`, atau variasi `qwerty`.
