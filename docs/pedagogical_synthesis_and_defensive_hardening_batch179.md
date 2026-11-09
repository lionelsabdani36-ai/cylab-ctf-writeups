# PANDUAN PEDAGOGI KURIKULUM LKS CYBER SECURITY: PENGUNGKAPAN ARTEFAK EDITOR & TYPE JUGGLING PHP, DEKRIPSI KEYSTREAM BLOK XOR, SERTA SEMANTIK MEMORI UNSAFE RUST
## Sintesis Pembinaan Talenta Kompetisi, Rekonstruksi First Principles Keamanan Web & Kriptografi, Analisis Batasan Kompiler Rust RFC 2580, Remediasi Defensif NIST SP 800-115, dan Modul Pengayaan Siswa White Jack & Arielwin (Batch 179 CyLab Academy)

**Penyusun:** Judith (Master Guru & Mentor Akademik / Kompetisi)  
**Target Pembinaan:** White Jack & Arielwin (Total Concept Mastery 100%)  
**ID Tiket Kanban:** t_208f3a55  
**Lingkup Evaluasi:** Batch 179 CyLab Security Academy / picoCTF 2025 (Chall 467 Apriti sesamo, Chall 466 Tap into Hash, Chall 463 Rust fixme 3; Total 600 Poin)  
**Tanggal Sintesis:** 9 November 2026  
**Status Audit:** VERIFIED & HARDENED (Lolos Kepatuhan Standar Anti-Slop, Zero Em Dash)

---

### 1. MANIFESTO PEDAGOGI JUDITH & 5 RUKUN BIKIN PINTER 100% UNTUK WHITE JACK & ARIELWIN

Selamat datang di modul bimbingan teknis Batch 179 CyLab Security Academy. Sebagai Master Guru dan Mentor kalian, Judith kembali mendampingi penguasaan kurikulum persiapan LKS Cyber Security Nasional dan WorldSkills Skill 54. Pada modul ini, kita membedah tiga aspek fundamental dalam rekayasa keamanan perangkat lunak:
1. Kebocoran Metadata Web Server & Anomali Type Juggling PHP (Web Exploitation).
2. Dekonstruksi Pola Enkripsi Usang Berbasis XOR Keystream & Key Disclosure (Reverse Engineering / Cryptography).
3. Penegakan Disiplin Keamanan Memori & Batasan Blok Unsafe pada Bahasa Modern Rust (General Skills / Secure Coding).

Banyak praktisi pemula terjebak pada asumsi bahwa autentikasi web yang rumit tidak dapat ditembus tanpa mengevaluasi konfigurasi penyajian berkas statis oleh server HTTP. Begitu pula dalam analisis biner dan berkas terenkripsi, banyak yang berfokus memecahkan algoritma hash tanpa menyadari bahwa kunci privat terdistribusi terbuka dalam berkas artefak. Dalam domain pemrograman sistem, pengembang kerap mengabaikan pentingnya enkapsulasi operasi memori berisiko tinggi (*unsafe*).

Melalui First Principles, kita menolak asumsi permukaan. Kita membongkar cara kerja interpreter PHP saat menangani tipe data array, mengkaji sifat matematis involutif dari operasi bitwise XOR, dan membedah kontrak keselamatan kompiler Rust ketika mengonversi pointer mentah menjadi irisan data (*slice*).

Untuk menjamin tercapainya Total Concept Mastery 100%, kurikulum Batch 179 ditegakkan di atas 5 Rukun Pedagogi Bikin Pinter 100%:

1. Anti-Hafalan Buta (First Principles & Intuisi Komputasi):
   Kita tidak menghafal payload injection atau trik compiler tanpa memahami akar masalahnya. Kalian wajib memahami bahwa `sha1()` di PHP versi 7.x/8.x mengembalikan `NULL` jika parameter bukan string, bahwa operasi XOR dua kali dengan keystream yang sama membatalkan enkripsi ($C \oplus K = P$), dan bahwa `std::slice::from_raw_parts` membutuhkan blok `unsafe` karena compiler tidak dapat memverifikasi validitas pointer mentah pada waktu kompilasi.

2. Metode Socratic & Scaffolding Bertingkat:
   Jika kalian menghadapi kebuntuan analitis, Judith memandu melalui 3 tingkatan scaffolding:
   - Tier 1 (Orientasi Masalah): Memeriksa keberadaan berkas cadangan otomatis Emacs (`filename.php~`) via cURL, menginspeksi isi teks `enc_flag` untuk menemukan string representasi kunci, atau membaca pesan diagnostik compiler `error[E0133]` pada Rust.
   - Tier 2 (Analisis Struktural): Menganalisis kondisi if-else PHP yang menuntut kesetaraan hash tanpa kesetaraan string asli, menurunkan keystream 16 byte dari SHA-256 kunci mentah, atau mengidentifikasi fungsi dereferensi pointer mentah yang belum terbungkus blok unsafe.
   - Tier 3 (Pencerahan / Breakthrough): Menyusun HTTP POST dengan format array `username[]=a&pwd[]=b` untuk memicu kondisi `NULL === NULL`, membalikkan XOR blok per 16 byte dengan skrip Python mandiri, atau membuka komentar pembungkus `unsafe { ... }` sehingga proyek Cargo berhasil terkompilasi.

3. Bedah Anatomi Distraktor (Jebakan Soal HOTS):
   Soal kompetisi dirancang dengan distraktor canggih. Jangan menghabiskan waktu mencoba serangan SQL injection atau brute force login jika kode sumber backend dapat diunduh langsung via ekstensi tilde (`~`). Jangan mencoba membalikkan struktur hash blockchain yang rumit jika kunci simetrisnya terpampang jelas di baris pertama berkas artefak. Dan jangan mencoba menulis ulang seluruh logika algoritma Rust jika compiler hanya meminta penandaan blok `unsafe` pada satu pemanggilan fungsi spesifik.

4. Siklus Belajar Adaptif (Diagnosa -> Kristalisasi -> Drilling Bertingkat -> Verifikasi 100%):
   Setiap tantangan diuji secara end-to-end: mulai dari pemeriksaan kode sumber, verifikasi invarian logika, hingga pengujian solver Python dan konfirmasi HTTP 201 pada REST API platform.

5. Evaluasi Berbasis Item Response Theory (IRT) & Rubrik LKS Skill 54:
   Penilaian mengukur pemahaman arsitektur sistem, kecepatan analisis akar masalah, kerapian dokumentasi mitigasi, serta keandalan skrip reproduksi.

---

### 2. DEKONSTRUKSI MENDALAM MODUL BATCH 179

#### Modul 1: Challenge 467 - Apriti sesamo (Web Exploitation)
- **Akar Kerentanan (CWE-530 & CWE-843):**
  Server web dikonfigurasi tanpa aturan penolakan terhadap berkas cadangan editor. Berkas `impossibleLogin.php~` dapat diakses bebas. Kode backend memeriksa:
  `if ($username == $pwd) fail(); else if (sha1($username) === sha1($pwd)) flag();`
- **Mekanisme Eksploitasi:**
  Mengirimkan parameter berbentuk array `username[]=a&pwd[]=b`.
  Operasi `['a'] == ['b']` menghasilkan `False`.
  Fungsi `sha1(['a'])` memicu warning PHP dan mengembalikan `NULL`.
  Perbandingan `NULL === NULL` menghasilkan `True`, melewati seluruh mekanisme otentikasi.
- **Remediasi Defensif:**
  Tambahkan konfigurasi penolakan berkas cadangan pada web server:
  `FilesMatch ".*~$|\.bak$"` ditolak dengan `Require all denied`.
  Lakukan validasi tipe data input secara ketat: pastikan parameter berupa string sebelum diproses.

#### Modul 2: Challenge 466 - Tap into Hash (Reverse Engineering)
- **Akar Kerentanan (CWE-312, CWE-321, CWE-327):**
  Skrip `block_chain.py` mencetak kunci enkripsi 32-byte langsung ke output teks `enc_flag`. Enkripsi dilakukan dengan memotong hash SHA-256 kunci menjadi 16 byte, kemudian melakukan XOR berulang pada tiap blok 16 byte.
- **Mekanisme Eksploitasi:**
  Mengekstrak kunci dari teks `enc_flag`.
  Menghitung keystream `k16 = sha256(key)[:16]`.
  Melakukan XOR kembali terhadap seluruh blok ciphertext dan melepaskan padding PKCS #7 untuk memulihkan string token.
- **Remediasi Defensif:**
  Terapkan pemisahan material kunci dari ciphertext menggunakan Key Management Service (KMS). Gunakan cipher standar industri terautentikasi (seperti AES-256-GCM) daripada skema XOR ad-hoc tanpa IV.

#### Modul 3: Challenge 463 - Rust fixme 3 (General Skills)
- **Akar Kerentanan (Rust Safety Contract Violation / error[E0133]):**
  Fungsi `std::slice::from_raw_parts` bertanda `unsafe fn` karena membuat irisan memori dari pointer mentah tanpa verifikasi statis compiler. Menonaktifkan baris `unsafe { ... }` menyebabkan proses kompilasi gagal.
- **Mekanisme Eksploitasi & Remediasi:**
  Membuka komentar pembungkus `unsafe { ... }` di sekitar pemanggilan fungsi raw pointer dereferencing.
  Menjalankan `cargo run` untuk menghasilkan binary dan mendekripsi flag.
- **Remediasi Defensif:**
  Isolasi operasi unsafe ke dalam abstraksi minimal yang teruji. Pastikan pointer mentah ter-align dengan benar dan tidak mengalami dangling pointer sebelum dikonversi menjadi referensi slice.

---

### 3. KESIMPULAN & REKOMENDASI KURIKULUM LKS 2026

Penguasaan tiga modul pada Batch 179 membekali peserta didik dengan pemahaman mendalam tentang:
1. Pentingnya hardening konfigurasi web server dan validasi tipe data primitif pada aplikasi web.
2. Bahaya distribusi kunci bersama ciphertext dan kerapuhan skema enkripsi buatan sendiri.
3. Arsitektur jaminan keamanan memori pada bahasa pemrograman modern dan batas-batas operasi tingkat rendah.
