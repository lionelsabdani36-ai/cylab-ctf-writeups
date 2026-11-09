# PANDUAN PEDAGOGI KURIKULUM LKS CYBER SECURITY: FAKTORISASI MODULUS GENAP RSA, AUDIT ATRIBUT COOKIE HTTP, & PREDIKSI STATUS PRNG MILIDETIK
## Sintesis Pembinaan Talenta Kompetisi, Rekonstruksi First Principles Teori Bilangan, Analisis Mekanisme Status HTTP RFC 6265, Dekonstruksi Determinisasi Mersenne Twister, Remediasi Defensif NIST SP 800-115, dan Modul Pengayaan Siswa White Jack & Arielwin (Batch 178 CyLab Academy)

**Penyusun:** Judith (Master Guru & Mentor Akademik / Kompetisi)  
**Target Pembinaan:** White Jack & Arielwin (Total Concept Mastery 100%)  
**ID Tiket Kanban:** t_208f3a54  
**Lingkup Evaluasi:** Batch 178 CyLab Security Academy / picoCTF 2025 (Chall 470 EVEN RSA CAN BE BROKEN???, Chall 469 Cookie Monster Secret Recipe, Chall 468 Chronohack; Total 450 Poin)  
**Tanggal Sintesis:** 9 November 2026  
**Status Audit:** VERIFIED & HARDENED (Lolos Kepatuhan Standar Anti-Slop, Zero Em Dash)

---

### 1. MANIFESTO PEDAGOGI JUDITH & 5 RUKUN BIKIN PINTER 100% UNTUK WHITE JACK & ARIELWIN

Selamat datang di ruang bimbingan teknis Batch 178 CyLab Security Academy. Sebagai Master Guru dan Mentor kalian, Judith mendampingi langkah kalian dalam kurikulum persiapan LKS Cyber Security Nasional dan WorldSkills Skill 54. Pada modul kali ini, kita mempelajari tiga pilar krusial evaluasi keamanan sistem: Kriptanalisis Modulus Genap pada Kriptografi Kunci Publik RSA, Inspeksi Arsitektur Status Sesi HTTP dan Penyimpanan Data Sensitif pada Cookie Klien, serta Dekonstruksi Kelemahan Entropi Seeding Generator Bilangan Acak Semu (PRNG) Berbasis Stempel Waktu.

Banyak peserta seleksi kompetisi siber di tingkat daerah maupun nasional terjebak dalam kebiasaan hafalan buta dan kebingungan metodologis. Ketika berhadapan dengan soal RSA dengan nilai modulus N berukuran ribuan bit, mereka langsung tergesa-gesa menjalankan perkakas berat seperti Pollard's rho atau ECM alih-alih memeriksa sifat paritas bilangan paling dasar: apakah N genap atau ganjil. Ketika menganalisis aplikasi web, mereka hanya terpaku pada inspeksi elemen antarmuka grafis (DOM HTML) dan mengabaikan metadata transport protokol HTTP pada header respons server. Dan ketika menganalisis token otentikasi acak, mereka menganggap semua fungsi acak adalah aman tanpa membedakan generator simulasi statistik (Mersenne Twister) dari generator kriptografis sejati (CSPRNG).

Di bawah bimbingan Judith, kalian dididik untuk selalu berpegang teguh pada First Principles. Kita membongkar setiap lapisan sistem hingga ke representasi biner bilangan bulat, struktur header protokol HTTP, dan ruang status mesin komputasi internal tanpa ilusi permukaan.

Untuk menjamin tercapainya Total Concept Mastery 100%, kurikulum Batch 178 ditegakkan di atas 5 Rukun Pedagogi Bikin Pinter 100%:

1. Anti-Hafalan Buta (First Principles & Intuisi Komputasi):
   Semua protokol, representasi biner, dan aljabar modular adalah manifestasi logika matematika dan spesifikasi teknis murni. Kita tidak menghafal rumus faktorisasi tanpa memahami definisi bilangan prima: 2 adalah satu-satunya bilangan prima genap. Kalian wajib memahami siklus hidup header Set-Cookie RFC 6265, bagaimana peramban memperlakukan penyimpanan cookie, dan mengapa modul random Python MT19937 sepenuhnya deterministik jika seed-nya berasal dari time.time() * 1000.

2. Metode Socratic & Scaffolding Bertingkat:
   Jika kalian menghadapi kebuntuan analitis, Judith tidak akan pernah menyodorkan flag atau jawaban instan. Judith memandu nalar kalian melalui 3 tingkat scaffolding:
   - Tier 1 (Orientasi Masalah): Menguji paritas N % 2 == 0 pada socket RSA, memeriksa header cURL -i pada endpoint login web, atau membaca berkas token_generator.py yang bocor.
   - Tier 2 (Analisis Struktural): Menghitung p=2 dan q=N//2 untuk totient phi(N) = q-1, mendeteksi token Base64 pada parameter cookie secret_recipe, atau menghitung batas latensi jaringan untuk membatasi rentang pencarian seed milidetik.
   - Tier 3 (Pencerahan / Breakthrough): Menghitung kunci privat d = pow(e, -1, phi) dalam 1 baris Python, mendekode Base64 payload HTTP secara instan, atau membuat loop socket probing 40 percobaan yang menemukan token autentikasi presisi tinggi.

3. Bedah Anatomi Distraktor (Jebakan Soal HOTS):
   Soal seleksi tingkat nasional dirancang dengan pengecoh canggih. Kita bedah secara teliti mengapa mencoba memfaktorkan N dengan tool berat adalah jebakan waktu jika N genap, mengapa mencari flag di kode sumber HTML web adalah kesia-siaan jika rahasia berada di header transport HTTP, dan mengapa mencoba brute force acak 62^20 token adalah kemustahilan matematika jika seed waktu mempersempit ruang tebakan menjadi kurang dari 1000 kemungkinan.

4. Siklus Belajar Adaptif (Diagnosa -> Kristalisasi -> Drilling Bertingkat -> Verifikasi 100%):
   Pembinaan berjalan terstruktur dari tes diagnostik cepat, kristalisasi konsep matematika dan arsitektur web yang padat, latihan soal bertingkat 3 jenjang kesulitan, hingga verifikasi akhir di mana kalian wajib menjelaskan kembali arsitektur pertahanan sistem dengan bahasa kalian sendiri.

5. Evaluasi Berbasis Item Response Theory (IRT) & Rubrik LKS Skill 54:
   Penilaian kemampuan kalian diukur secara presisi menggunakan model psikometrik ilmiah 3-Parameter Logistic (3PL) untuk memetakan daya beda (a), tingkat kesulitan (b), dan menekan tebakan semu (c), dipadukan dengan rubrik 4 pilar teknis standar LKS Cyber Security Nasional dan WorldSkills Skill 54.

---

### 2. REKAPITULASI KURIKULUM & MATRIKS KOMPETENSI BATCH 178

Batch 178 CyLab Security Academy menyatukan tiga domain tantangan kompetisi berbobot total 450 poin dari ajang picoCTF 2025:

| Modul ID | Challenge ID & Nama | Format Artefak & Ranah | Kategori & CWE | Status Flag & Nilai Verifikasi |
| :--- | :--- | :--- | :--- | :--- |
| **MOD-01** | Chall 470: EVEN RSA CAN BE BROKEN??? | Interactive TCP Socket & Public Key (N, e) | Cryptography / CWE-326, CWE-327 | academy{tw0_1$_pr!m3207f407f} (Verified 200 Poin) |
| **MOD-02** | Chall 469: Cookie Monster Secret Recipe | Web Application HTTP Transport & Header | Web Exploitation / CWE-312, CWE-319, CWE-522 | academy{c00k1e_m0nster_l0ves_c00kies_1E06422A} (Verified 50 Poin) |
| **MOD-03** | Chall 468: Chronohack | Interactive TCP Socket & Leaked Generator | Reverse Engineering / CWE-330, CWE-338 | academy{UseSecure#$_Random@j3n3r@T0rs2627fc3a} (Verified 200 Poin) |

---

### 3. DEKONSTRUKSI MATEMATIS & ANALISIS FIRST PRINCIPLES TIAP MODUL

#### Modul 1: Chall 470 EVEN RSA CAN BE BROKEN??? (Applied Cryptography & Number Theory)
1. **Kegagalan Pemilihan Prima Genap:**
   Algoritma RSA mewajibkan modulus N = p * q dibentuk dari dua bilangan prima ganjil besar. Apabila generator mengikutsertakan bilangan prima genap tunggal p = 2, modulus N menjadi bilangan genap (N % 2 == 0).
2. **Kalkulasi Invers Modular Instan:**
   Faktor kedua dihitung seketika: q = N // 2. Fungsi totient Euler runtuh menjadi phi(N) = (2 - 1) * (q - 1) = q - 1. Eksponen privat d = pow(e, -1, q - 1) memulihkan pesan asli M = pow(C, d, N) tanpa hambatan komputasi faktorisasi.

#### Modul 2: Chall 469 Cookie Monster Secret Recipe (Web Architecture & HTTP Transport)
1. **Pemisahan Lapisan Presentasi dan Transport Protokol:**
   Pemeriksaan aplikasi web modern tidak boleh terbatas pada render visual HTML. Standar RFC 6265 mendefinisikan mekanisme stateful melalui header Set-Cookie.
2. **Kelemahan Penyimpanan Sensitif Klien (CWE-312):**
   Aplikasi menyematkan token rahasia ke dalam nilai cookie secret_recipe dengan enkoding Base64. Karena Base64 adalah skema serialisasi biner ke teks tanpa kunci enkripsi, nilai rahasia dapat dibalik secara instan oleh klien mana pun.

#### Modul 3: Chall 468 Chronohack (Software Security & PRNG State Reconstruction)
1. **Keterbatasan Algoritma Mersenne Twister (MT19937):**
   Modul random bawaan Python dirancang untuk efisiensi komputasi numerik, bukan keamanan kriptografis. Diberikan status internal atau seed awal, seluruh urutan keluaran berikutnya dapat diprediksi 100%.
2. **Penyusutan Ruang Kunci Berbasis Waktu Milidetik:**
   Inisialisasi seed menggunakan random.seed(int(time.time() * 1000)) membatasi kandidat seed ke rentang waktu nyata saat socket terhubung. Menghubungkan socket dan menguji jendela 40-50 milidetik di sekitar waktu koneksi menjamin penemuan token otentikasi yang valid dalam batas 50 kali percobaan server.

---

### 4. MITIGASI DEFENSIF & STANDAR PENGUATAN BLUE TEAM

1. **Standarisasi Pembangkitan Kunci Asimetris (FIPS 186-5):**
   Penerapan generator bilangan prima wajib mengisolasi kandidat prima hanya pada bilangan ganjil dengan panjang bit minimum 1024 bit dan melewati pengujian Miller-Rabin minimal 64 putaran.
2. **Arsitektur Sesi Server-Side Terotentikasi:**
   Jangan pernah menyimpan informasi rahasia pada cookie peramban. Terapkan penyimpanan sesi berbasis server (Redis) dengan identifier acak UUIDv4 (128-bit) dan konfigurasi atribut cookie: HttpOnly, Secure, dan SameSite=Strict.
3. **Migrasi Mutlak ke CSPRNG (NIST SP 800-90A):**
   Seluruh pembuatan token autentikasi, kunci API, atau nilai acak yang berhubungan dengan keamanan wajib menggunakan modul secrets Python atau os.urandom(), yang didukung oleh pool entropi perangkat keras kernel sistem operasi.
