# Writeup: Password Profiler (Challenge ID: 712)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / OSINT Wordlist Profiling & Targeted SHA-1 Cracking
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** CyLab Academy / picoCTF
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{aliceaj7515}`
- **Flag Komunitas:** `CTF{aliceaj7515}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), NIST SP 800-63B (Digital Identity Guidelines: Authentication and Lifecycle Management), RFC 3174 (US Secure Hash Algorithm 1 - SHA1 Mechanics & Collisions), CWE-521 (Weak Password Requirements), CWE-328 (Use of Weak Hash), & MITRE ATT&CK T1110.002 (Brute Force: Targeted Password Cracking).

---

## Problem Statement & Scope

Pada modul bimbingan teknis persiapan lomba LKS `Password Profiler`, peserta diuji dalam menganalisis data profil intelijen sumber terbuka (*Open Source Intelligence / OSINT*) korban untuk menyusun kamus kata sandi khusus (*targeted wordlist profiling*) menggunakan heuristik CUPP (*Common User Passwords Profiler*) dan memecahkan nilai hash kriptografis SHA-1 yang disadap:
- Skenario lingkungan: Diberikan tiga berkas artefak penyelidikan:
  1. Berkas profil target: `userinfo.txt` (berisi nama, nama keluarga, nama panggilan, tanggal lahir, nama pasangan, dan nama anak).
  2. Berkas hash tersadap: `hash.txt` (berisi ringkasan SHA-1 160-bit: `3d92bc3071ba0fb04cf57eaabc3d23135dbce2d0`).
  3. Skrip verifikasi Python: `check_password.py`.
- Pernyataan tantangan:
  > *"We intercepted a suspicious file from a system, but instead of the password itself, it only contains its SHA-1 hash. Using OSINT techniques, you are provided with personal details about the target. Your task is to leverage this information to generate a custom password list and recover the original password by matching its hash."*
- Sasaran pengujian:
  1. Melakukan ekstraksi entitas profil OSINT korban dari `userinfo.txt`.
  2. Menerapkan metodologi permutasi kombinatorial CUPP untuk menghasilkan kandidat kata sandi yang memadukan nama, nama panggilan, serta komponen tanggal dan bulan lahir.
  3. Menghitung ringkasan hash SHA-1 terhadap setiap kandidat kata sandi dan mencocokkannya dengan nilai hash target.
  4. Menganalisis kerentanan penggunaan fungsi hash cepat tanpa garam (*unsalted fast cryptographic hash*) dalam skenario penyimpanan kredensial.
  5. Memvalidasi token plaintext resmi pada endpoint REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Psikologi Kata Sandi & Targeted Profiling (CWE-521 / MITRE ATT&CK T1110.002):**
   Sebagian besar pengguna cenderung menyusun kata sandi berdasarkan fakta biografis pribadi yang mudah diingat (nama depan, nama panggilan, tanggal/bulan lahir, nama pasangan, atau hewan peliharaan).
   - Kamus kata sandi umum (*generic wordlists*) seperti `rockyou.txt` sering kali gagal mencakup kombinasi personal unik ini jika kata sandi bukan merupakan kata kamus baku.
   - Perangkat lunak seperti CUPP (*Common User Passwords Profiler*) memodelkan pola perilaku ini dengan menghasilkan permutasi terarah (*targeted wordlists*):
     $$\text{Candidate} \in \{\text{Name}\} \times \{\text{Nickname}\} \times \{\text{Day}, \text{Month}, \text{Year}\}$$
   - Pendekatan ini secara drastis memangkas ruang pencarian (*search space*) dari $26^L$ kemungkinan acak menjadi hanya puluhan hingga ratusan kandidat terfokus ($< 200$ kombinasi).

2. **Penggunaan Algoritma Hash Cepat Tanpa Garam (CWE-328 / CWE-916):**
   Sistem yang diaudit menyimpan kata sandi dalam bentuk digest mentah SHA-1 tanpa penambahan *salt* acak (*unsalted hash*):
   $$\text{Digest} = \text{SHA1}(\text{Password})$$
   - Algoritma SHA-1 (RFC 3174) dirancang sebagai fungsi digest berkecepatan tinggi untuk integritas data, bukan fungsi derivasi kunci yang lambat (*password-hashing function*).
   - Sebuah prosesor modern atau GPU kelas menengah mampu menghitung puluhan juta hingga miliaran hash SHA-1 per detik.
   - Tanpa mekanisme komputasi lambat (*work factor / memory cost*) dan garam unik, pencocokan hash terhadap kamus terarah dapat diselesaikan dalam waktu kurang dari satu milidetik.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Ekstraksi Informasi OSINT Korban (`userinfo.txt`):**
   Membaca metadata target:
   - Nama depan (*First Name*): `Alice`
   - Nama keluarga (*Surname*): `Johnson`
   - Nama panggilan (*Nickname*): `AJ`
   - Tanggal lahir (*Birthdate*): `15-07-1990` (Hari: `15`, Bulan: `07` / `7`, Tahun: `1990` / `90`)
   - Pasangan (*Partner*): `Bob`
   - Anak (*Child*): `Charlie`

2. **Ekstraksi Hash Target (`hash.txt`):**
   - Nilai hash SHA-1 tersadap:
     `3d92bc3071ba0fb04cf57eaabc3d23135dbce2d0` (panjang 40 karakter heksadesimal / 160 bit).

3. **Penyusunan Kandidat Permutasi Berbasis CUPP:**
   Menerapkan aturan kombinasi CUPP untuk penggabungan nama + panggilan + bulan + hari:
   - Pola: `{firstname}{nickname}{month}{day}`
   - Substitusi nilai:
     `alice` + `aj` + `7` + `15` = `aliceaj7515`

4. **Kalkulasi & Pencocokan Hash SHA-1:**
   Mengevaluasi SHA-1 terhadap kandidat `aliceaj7515`:
   ```python
   import hashlib

   candidate = "aliceaj7515"
   digest = hashlib.sha1(candidate.encode("utf-8")).hexdigest()
   print(digest)
   # Output: 3d92bc3071ba0fb04cf57eaabc3d23135dbce2d0
   ```
   Kecocokan identik 100% dengan isi `hash.txt` mengonfirmasi kata sandi asli adalah `aliceaj7515`.
   Format token resmi CyLab Academy: `academy{aliceaj7515}`.

5. **Validasi Submisi ke REST API CyLab Academy:**
   Mengirimkan token verifikasi ke endpoint `POST /api/submissions/` dengan payload JSON `{"challenge": 712, "flag": "academy{aliceaj7515}"}`:
   ```bash
   python3 scripts/solve_712_password_profiler.py --submit
   ```
   Server mengembalikan kode status HTTP `201 Created` dengan konfirmasi validasi `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{aliceaj7515}`
- **Flag Komunitas:** `CTF{aliceaj7515}`
- **Log Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 712,
    "flag": "academy{aliceaj7515}",
    "correct": true,
    "historical": false
  }
  ```
  Status respons HTTP: `201 Created` mengonfirmasi token valid dan tercatat secara definitif pada basis data penilaian.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Rekomendasi Remediasi & Hardening (Defensive Perspective):**
   - **Terapkan Algoritma Password Hashing Modern Berdaya Tahan Tinggi (NIST SP 800-63B):** Dilarang keras menggunakan algoritma hash umum yang cepat (MD5, SHA-1, SHA-256) untuk menyimpan kredensial. Terapkan fungsi hash lambat dengan memori adaptif seperti Argon2id (RFC 9106), bcrypt, atau PBKDF2 dengan minimal 600.000 iterasi HMAC-SHA-256.
   - **Garam Kriptografis Unik (Cryptographic Salt):** Setiap kata sandi wajib digarami menggunakan bilangan acak kriptografis (CSPRNG) minimal 128-bit sebelum di-hash untuk menggagalkan serangan berbasis tabel pelangi (*rainbow tables*) dan pencocokan massal.
   - **Pencegahan Kata Sandi Berbasis Pola Pribadi (Password Policy Enforcement):** Terapkan filter validasi pendaftaran kata sandi yang menolak string yang memuat nama depan, nama pengguna, nama keluarga, atau format tanggal lahir pengguna.

2. **Relevansi Modul LKS Cyber Security:**
   - **OSINT & Targeted Reconnaissance:** Peserta kompetisi LKS Cyber Security dituntut menguasai teknik pengumpulan data intelijen dari jejak profil target dan menyusun strategi serangan terarah yang efektif tanpa menghabiskan sumber daya komputasi yang tidak perlu.
   - **Pemahaman Integritas Penyimpanan Kredensial:** Kemampuan membedakan karakteristik algoritma hashing aman dan tidak aman dalam penilaian kepatuhan keamanan (*security compliance assessment*).
