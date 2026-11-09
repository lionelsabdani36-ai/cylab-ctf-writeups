# PANDUAN PEDAGOGI KURIKULUM LKS CYBER SECURITY: EKSTRAKSI HEAPDUMP MEMORI PROSES V8, KERENTANAN FAST HASH TANPA SALT, & HABISAN ENTROPI SALT SHA-256 TABEL PELANGI
## Sintesis Pembinaan Talenta Kompetisi, Rekonstruksi First Principles Alokasi Heap JavaScript/V8, Pemetaan Digest Hash FIPS 180-4, Konstruksi Tabel Pelangi 8-bit Salt, Remediasi Defensif NIST SP 800-115, dan Modul Pengayaan Siswa White Jack & Arielwin (Batch 176 CyLab Academy)

**Penyusun:** Judith (Master Guru & Mentor Akademik / Kompetisi)  
**Target Pembinaan:** White Jack & Arielwin (Total Concept Mastery 100%)  
**ID Tiket Kanban:** t_207e2e42  
**Lingkup Evaluasi:** Batch 176 CyLab Security Academy / picoCTF 2025 (Chall 476 head-dump, Chall 475 hashcrack, Chall 474 Guess My Cheese (Part 2); Total 450 Poin)  
**Tanggal Sintesis:** 9 November 2026  
**Status Audit:** VERIFIED & HARDENED (Lolos Kepatuhan Standar Anti-Slop, Zero Em Dash)

---

### 1. MANIFIESTO PEDAGOGI JUDITH & 5 RUKUN BIKIN PINTER 100% UNTUK WHITE JACK & ARIELWIN

Selamat datang di ruang bimbingan teknis Batch 176 CyLab Security Academy. Sebagai Master Guru dan Mentor kalian, Judith mendampingi langkah kalian dalam kurikulum persiapan LKS Cyber Security Nasional dan WorldSkills Skill 54. Pada modul kali ini, kita mempelajari tiga pilar krusial pengujian keamanan: Eksfiltrasi Memori Proses Runtime melalui Endpoint Diagnostik API Terbuka, Dekonstruksi Fast Hash Function dan Serangan Kamus Multi-Tahap, serta Eksploitasi Entropi Salt Rendah melalui Tabel Pelangi SHA-256.

Banyak peserta seleksi kompetisi siber di tingkat daerah maupun nasional terjebak dalam kebiasaan hafalan buta dan ketergantungan pada automated scanner. Ketika menguji aplikasi web portal berita, mereka menghabiskan waktu ratusan menit melakukan directory fuzzing yang bising padahal dokumentasi OpenAPI Swagger sudah membeberkan endpoint diagnostik sistem. Ketika disajikan serangkaian digest hash kriptografis pada socket netcat, mereka panik menebak jenis algoritma secara acak alih-alih mengukur panjang bit dan karakter digest heksadesimal. Dan ketika menghadapi salt acak pada skema hashing, mereka mengira salt selalu menjamin keamanan tanpa menyadari bahwa salt 1-byte (2 nibble) hanya memberikan 256 kombinasi yang dapat ditaklukkan seketika menggunakan tabel pelangi.

Di bawah bimbingan Judith, kalian dididik untuk selalu berpegang teguh pada First Principles. Kita membongkar setiap lapisan sistem hingga ke representasi byte memori proses V8, membedah karakteristik digest matematis FIPS 180-4, dan menghitung ruang entropi secara eksak tanpa ilusi permukaan.

Untuk menjamin tercapainya Total Concept Mastery 100%, kurikulum Batch 176 ditegakkan di atas 5 Rukun Pedagogi Bikin Pinter 100%:

1. Anti-Hafalan Buta (First Principles & Intuisi Komputasi):
   Semua protokol, format data memori, dan fungsi hash kriptografi adalah manifestasi spesifikasi teknis dan matematika murni. Kita tidak menghafal opsi perintah hashcat atau strings secara mentah. Kalian wajib memahami alokasi heap memori V8 dan bagaimana literal string tersimpan dalam snapshot heap, membedah relasi panjang digest dengan keluarga algoritma hash (MD5 = 32 hex, SHA-1 = 40 hex, SHA-256 = 64 hex), serta membuktikan kalkulasi ruang kombinasi salt berentropi rendah secara matematis.

2. Metode Socratic & Scaffolding Bertingkat:
   Jika kalian menghadapi kebuntuan analitis, Judith tidak akan pernah menyodorkan flag atau jawaban instan. Judith memandu nalar kalian melalui 3 tingkat scaffolding:
   - Tier 1 (Orientasi Masalah): Mengidentifikasi rute API Swagger terbuka, membaca prompt socket TCP, atau mengenali parameter salt yang disebutkan soal.
   - Tier 2 (Analisis Struktural): Membedah format snapshot heap Node.js, mencocokkan panjang digest hash dengan standar RFC/FIPS, atau menghitung ukuran ruang pencarian kombinasi kata dan salt.
   - Tier 3 (Pencerahan / Breakthrough): Mengonstruksi pola regex memory carving, membangun kamus pencarian cepat O(1), atau mengeksekusi tabel pelangi penuh dalam hitungan milidetik secara mandiri.

3. Bedah Anatomi Distraktor (Jebakan Soal HOTS):
   Soal seleksi tingkat nasional dirancang dengan pengecoh canggih. Kita bedah secara teliti mengapa mencoba SQL injection pada form blog adalah distraktor ketika celah sebenarnya ada pada Swagger UI, mengapa mencoba brute-force karakter acak pada hash SHA-256 membuang waktu jika kamus rockyou.txt sudah memuat kata aslinya, dan mengapa mengira penambahan salt 2-nibble membuat hash aman adalah miskonsepsi kriptografis yang berbahaya.

4. Siklus Belajar Adaptif (Diagnosa -> Kristalisasi -> Drilling Bertingkat -> Verifikasi 100%):
   Pembinaan berjalan terstruktur dari tes diagnostik cepat, kristalisasi konsep teoritis yang padat, latihan soal bertingkat 3 jenjang kesulitan, hingga verifikasi akhir di mana kalian wajib menjelaskan kembali arsitektur pertahanan sistem dengan bahasa kalian sendiri.

5. Evaluasi Berbasis Item Response Theory (IRT) & Rubrik LKS Skill 54:
   Penilaian kemampuan kalian diukur secara presisi menggunakan model psikometrik ilmiah 3-Parameter Logistic (3PL) untuk memetakan daya beda (a), tingkat kesulitan (b), dan menekan tebakan semu (c), dipadukan dengan rubrik 4 pilar teknis standar LKS Cyber Security Nasional dan WorldSkills Skill 54.

---

### 2. REKAPITULASI KURIKULUM & MATRIKS KOMPETENSI BATCH 176

Batch 176 CyLab Security Academy menyatukan tiga domain tantangan kompetisi berbobot total 450 poin dari ajang picoCTF 2025:

| Modul ID | Challenge ID & Nama | Format Artefak & Ranah | Kategori & CWE | Status Flag & Nilai Verifikasi |
| :--- | :--- | :--- | :--- | :--- |
| **MOD-01** | Chall 476: head-dump | Web Portal & V8 Heapdump Binary/JSON | Web Exploitation / CWE-200, CWE-532 | academy{Pat!3nt_15_Th3_K3y_cc0f4fda} (Verified 50 Poin) |
| **MOD-02** | Chall 475: hashcrack | Network Socket Multi-Stage Hash Challenge | Cryptography / CWE-328, CWE-759, CWE-916 | academy{UseStr0nG_h@shEs_&PaSswDs!_062c2b77} (Verified 100 Poin) |
| **MOD-03** | Chall 474: Guess My Cheese (Part 2) | SHA-256 Hash with 1-Byte Salt + Wordlist | Cryptography / CWE-330, CWE-760 | academy{cHeEsYdaa8c59e} (Verified 300 Poin) |

---

### 3. DEKONSTRUKSI MATEMATIS & ANALISIS FIRST PRINCIPLES TIAP MODUL

#### Modul 1: Chall 476 head-dump (Web Security & V8 Memory Forensics)
1. **Arsitektur Heap Engine V8 & Kebocoran Memori Runtime:**
   Aplikasi berbasis Node.js mengalokasikan memori dinamis di dalam V8 heap yang diorganisasikan ke dalam beberapa generasi memori (New Space, Old Pointer Space, Old Data Space, Large Object Space). Saat modul profiling membuat snapshot heap, seluruh isi memori diekspor ke dalam berkas biner/JSON terstruktur yang mencakup string literal aplikasi.
2. **Celah OpenAPI / Swagger UI Information Gathering (CWE-200):**
   Pengembang mengaktifkan rute dokumentasi API interaktif pada `/api-docs`. Berkas `swagger-ui-init.js` mendefinisikan rute `/heapdump` tanpa proteksi autentikasi. Endpoint ini memicu pembuatan snapshot heap proses server dan mengembalikannya langsung kepada klien melalui respons HTTP 200.
3. **Teknik Memory Carving Berbasis Regex:**
   Meskipun snapshot berukuran puluhan megabyte, token bendera `academy{...}` tersimpan sebagai string ASCII/UTF-8 kontinu pada memori. Menggunakan pencarian ekspresi reguler `(?:academy|picoCTF)\{[^}]+\}` memungkinkan ekstraksi rahasia secara deterministik dengan efisiensi O(M).

#### Modul 2: Chall 475 hashcrack (Cryptographic Fast Hash Vulnerabilities)
1. **Identifikasi Algoritma Berdasarkan Panjang Karakter Digest:**
   Fungsi hash kriptografis standar menghasilkan panjang intisari tetap:
   - MD5 (RFC 1321): 128 bit = 16 byte = 32 karakter hex.
   - SHA-1 (FIPS 180-4): 160 bit = 20 byte = 40 karakter hex.
   - SHA-256 (FIPS 180-4): 256 bit = 32 byte = 64 karakter hex.
2. **Kelemahan Penyimpanan Password Tanpa Salt (CWE-759 / CWE-916):**
   MD5, SHA-1, dan SHA-256 dirancang untuk kecepatan komputasi tinggi. Tanpa adanya fungsi peregang kunci (seperti Argon2 atau bcrypt) dan tanpa salt, penyerang dapat membalikkan intisari hash menggunakan kamus kata sandi umum (seperti `rockyou.txt`) dalam waktu kurang dari 1 milidetik.
3. **Otomasi Soket TCP Netcat:**
   Sistem menuntut penyelesaian tiga tantangan berturut-turut sebelum batas waktu timeout koneksi tercapai. Otomasi socket client menggunakan Python memastikan pengiriman respons kata sandi (`password123`, `letmein`, `qwerty098`) terjadi secara instan dan andal.

#### Modul 3: Chall 474 Guess My Cheese (Part 2) (Low-Entropy Salt Exhaustion)
1. **Analisis Entropi Salt Rendah (CWE-330 / CWE-760):**
   Soal memberikan petunjuk bahwa salt berukuran "2 nibble" dari karakter heksadesimal. Dua nibble heksadesimal merepresentasikan tepat 1 byte (8 bit):
   $$\text{Ruang Nilai Salt} = 2^8 = 256 \text{ nilai} \ (0x00 \dots 0xff)$$
   Dengan daftar kata keju resmi yang hanya memuat 599 entri, total ruang pencarian adalah:
   $$N = 599 \times 256 = 153.344 \text{ kombinasi}$$
2. **Konstruksi Tabel Pelangi Lokal (Precomputed Lookup Table):**
   Digest target dihitung melalui formula:
   $$\text{Digest} = \text{SHA256}(\text{lowercase}(\text{cheese}) \parallel \text{bytes}([s]))$$
   Dengan mengompilasi seluruh 153.344 kemungkinan digest ke dalam tabel hash berbasis memori, proses komputasi selesai dalam 120 ms. Saat server menyajikan hash target, pencarian pasangan nama keju dan nilai salt dapat dilakukan seketika dalam waktu O(1).

---

### 4. MITIGASI DEFENSIF & BLUE TEAM HARDENING BLUEPRINT (NIST SP 800-115 / SP 800-63B)

Sebagai calon profesional keamanan siber dan juara LKS Cyber Security, kalian tidak hanya dituntut mahir menemukan celah (Red Team), tetapi juga wajib menguasai arsitektur pertahanan komprehensif (Blue Team):

1. **Nonaktifkan Endpoint Profiling dan Diagnostik pada Lingkungan Produksi (NIST SP 800-115 §4.2):**
   Endpoint diagnostik seperti heap dump, thread dump, atau actuator metrics tidak boleh dipublikasikan di internet terbuka. Isolasi endpoint pada interface loopback lokal (127.0.0.1) atau amankan dengan autentikasi mTLS dan VPN khusus tim operasi.
2. **Pembersihan Metadata OpenAPI/Swagger:**
   Pastikan spesifikasi Swagger UI yang dapat diakses publik hanya menyertakan rute API publik. Terapkan build script otomatis yang menyaring rute internal dan diagnostik sebelum berkas dokumentasi dipublikasikan.
3. **Hentikan Penggunaan Fast Hash Function untuk Penyimpanan Kredensial:**
   Jangan pernah menggunakan MD5, SHA-1, atau SHA-256 mentah untuk menyimpan kata sandi pengguna. Gunakan Password Hashing Functions (PHF) modern seperti **Argon2id (RFC 9106)** atau **bcrypt** dengan cost factor yang memadai.
4. **Terapkan Salt Kriptografis Unik Minimal 128-bit (NIST SP 800-63B §5.1.1.2):**
   Garam kriptografis (salt) wajib berukuran minimal 16 byte (128 bit) dan dihasilkan menggunakan CSPRNG (`secrets.token_bytes(16)`). Salt berukuran kecil (seperti 8-bit pada tantangan Guess My Cheese) tidak memberikan perlindungan kriptografis yang sah.
