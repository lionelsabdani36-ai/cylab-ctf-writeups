# PANDUAN PEDAGOGI KURIKULUM LKS CYBER SECURITY: SISTEM PEMINJAMAN RUST & MUTABILITAS, SINTAKS DASAR KOMPILER, SERTA STEGANOGRAFI SPASIAL LSB CITRA DIGITAL PNG
## Sintesis Pembinaan Talenta Kompetisi, Rekonstruksi First Principles Keamanan Memori & Forensik Digital, Analisis Batasan Kompiler Rust RFC 2094, Rekonstruksi Defiltering RFC 2083, Remediasi Defensif NIST SP 800-115, dan Modul Pengayaan Siswa White Jack & Arielwin (Batch 180 CyLab Academy)

**Penyusun:** Judith (Master Guru & Mentor Akademik / Kompetisi)  
**Target Pembinaan:** White Jack & Arielwin (Total Concept Mastery 100%)  
**ID Tiket Kanban:** t_208f3a56  
**Lingkup Evaluasi:** Batch 180 CyLab Security Academy / picoCTF 2025 (Chall 462 Rust fixme 2, Chall 461 Rust fixme 1, Chall 460 RED; Total 300 Poin)  
**Tanggal Sintesis:** 9 November 2026  
**Status Audit:** VERIFIED & HARDENED (Lolos Kepatuhan Standar Anti-Slop, Zero Em Dash)

---

### 1. MANIFESTO PEDAGOGI JUDITH & 5 RUKUN BIKIN PINTER 100% UNTUK WHITE JACK & ARIELWIN

Selamat datang di modul bimbingan teknis Batch 180 CyLab Security Academy. Sebagai Master Guru dan Mentor kalian, Judith mendampingi akselerasi kurikulum persiapan LKS Cyber Security Nasional dan WorldSkills Skill 54. Pada Batch 180 ini, kita mengintegrasikan dua pilar krusial dalam domain rekayasa keamanan:
1. Keamanan Memori dan Kontrak Tipe Kompiler Rust: Sistem Peminjaman (*Borrowing*), Mutabilitas Eksplisit, dan Validasi Pohon Sintaks Abstrak (AST) pada Waktu Kompilasi (General Skills / Secure Coding).
2. Forensik Digital Wadah Multimedia: Dekonstruksi Chunk Metadata PNG, Rekonstruksi Algoritma Defiltering Scanline RFC 2083, dan Ekstraksi Steganografi LSB Multi-Kanal RGBA (Digital Forensics).

Banyak peserta kompetisi pemula merasa gentar saat menghadapi pesan galat (*error diagnostics*) dari kompiler bahasa tingkat rendah seperti Rust, atau sebaliknya mengabaikan informasi berharga yang disampaikan oleh kompiler. Padahal, kompiler Rust dirancang sebagai alat bantu pembuktian formal (*formal verification assistant*) yang membimbing pengembang menuju kode bebas celah korupsi memori (*zero memory-corruption*). Di ranah forensik digital, banyak pemula bergantung sepenuhnya pada automated tools (seperti `zsteg` atau `binwalk`) tanpa memahami mengapa sebuah citra digital harus didefilter terlebih dahulu sebelum bit-bit tersembunyinya dapat dibaca secara akurat.

Melalui First Principles, kita membedah kontrak peminjaman Rust (aturan *aliasing XOR mutability*), menguji parsing pemformatan makro pada waktu kompilasi, serta menurunkan implementasi defiltering matematis RFC 2083 dari nol tanpa bantuan pustaka pihak ketiga.

Untuk menjamin tercapainya Total Concept Mastery 100%, kurikulum Batch 180 ditegakkan di atas 5 Rukun Pedagogi Bikin Pinter 100%:

1. Anti-Hafalan Buta (First Principles & Intuisi Komputasi):
   Kita tidak sekadar menambahkan tanda `&mut` atau tanda titik koma `;` tanpa mengerti arsitektur di baliknya. Kalian wajib memahami bahwa referensi immutable `&T` menjamin data tidak akan berubah selama pembacaan aktif, bahwa mutabilitas menuntut deklarasi eksplisit `let mut` dan `&mut T` guna mencegah *data race*, bahwa makro `println!` memeriksa kesesuaian placeholder kurung kurawal `{}` pada fase kompilasi untuk mencegah kerentanan format string (CWE-134), dan bahwa LSB citra PNG terikat pada filter prediktif scanline sebelum kompresi Deflate.

2. Metode Socratic & Scaffolding Bertingkat:
   Jika menghadapi kebuntuan teknis, Judith memandu melalui 3 tingkatan scaffolding:
   - Tier 1 (Orientasi Masalah): Membaca diagnostik compiler `error[E0596]` (cannot borrow as mutable) pada Challenge 462, `error: expected ';'` pada Challenge 461, atau mengekstrak chunk teks `tEXt` pada `red.png` yang menampilkan puisi akrostik berawalan "CHECK LSB".
   - Tier 2 (Analisis Struktural): Menelusuri rantai kepemilikan variabel dari fungsi pemanggil `main()` ke fungsi penerima `decrypt()` pada Rust, atau membedah struktur byte chunk `IDAT` PNG dan membaca byte penanda tipe filter baris (None, Sub, Up, Average, Paeth).
   - Tier 3 (Pencerahan / Breakthrough): Memperbaiki tanda tangan fungsi menjadi `&mut String` dan melewatkan `&mut party_foul`, memperbaiki kata kunci `return;` dan placeholder `{}` pada makro, serta menerapkan loop defiltering inversi pada Python untuk mengekstrak string Base64 dari bit terendah kanal RGBA.

3. Bedah Anatomi Distraktor (Jebakan Soal HOTS):
   Soal kompetisi memuat berbagai distraktor. Pada tantangan Rust, jangan mencoba menulis ulang algoritma XOR jika kesalahan hanya terletak pada sintaks peminjaman referensi dan terminator baris. Pada tantangan citra PNG, jangan terjebak melakukan brute force password Steghide atau memecahkan algoritma enkripsi eksotis jika metadata gambar secara terang-terangan memberikan petunjuk akrostik vertikal "CHECK LSB" dan muatannya tersimpan polos dalam format Base64.

4. Siklus Belajar Adaptif (Diagnosa -> Kristalisasi -> Drilling Bertingkat -> Verifikasi 100%):
   Seluruh tantangan divalidasi secara multi-dimensi: mulai dari kompilasi lokal cargo, eksekusi modul Python mandiri, hingga verifikasi token langsung pada endpoint REST API CyLab (`HTTP 201 Created`).

5. Evaluasi Berbasis Item Response Theory (IRT) & Rubrik LKS Skill 54:
   Penilaian mencakup pemahaman mendalam tentang standar RFC, kepatuhan keamanan CWE, kecepatan resolusi galat, dan kebersihan implementasi solver.

---

### 2. DEKONSTRUKSI MENDALAM MODUL BATCH 180

#### Modul 1: Challenge 462 - Rust fixme 2 (General Skills)
- **Akar Kerentanan (CWE-843 & CWE-662):**
  Fungsi `decrypt` bermaksud memutasi string yang dipinjam (`borrowed_string.push_str(...)`), namun parameter fungsi dideklarasikan sebagai referensi immutable `&String`. Selain itu, variabel sumber `party_foul` diinisialisasi tanpa kata kunci `mut` dan dilewatkan sebagai referensi immutable `&party_foul`.
- **Mekanisme Penyelesaian:**
  1. Ubah parameter fungsi penerima: `borrowed_string: &mut String`.
  2. Ubah inisialisasi variabel di fungsi pemanggil: `let mut party_foul = ...`.
  3. Ubah argumen pemanggilan fungsi: `decrypt(encrypted_buffer, &mut party_foul);`.
  4. Kompilasi dan jalankan dengan `cargo run` untuk memicu dekripsi token: `academy{4r3_y0u_h4v1n5_fun_y31?}`.
- **Remediasi Defensif:**
  Terapkan prinsip *immutability by default* pada seluruh perancangan arsitektur perangkat lunak. Batasi mutabilitas hanya pada lingkup yang mutlak membutuhkan perubahan status, dan pastikan tidak ada referensi alias lain yang aktif saat mutasi berlangsung guna mencegah kerentanan konkurensi.

#### Modul 2: Challenge 461 - Rust fixme 1 (General Skills)
- **Akar Kerentanan (CWE-843 & CWE-704):**
  Ketidaksesuaian tata bahasa dasar Rust:
  1. Ketiadaan titik koma terminator pada deklarasi variabel kunci: `let key = String::from("CSUCKS")`.
  2. Penggunaan identifier tidak terdefinisi `ret;` sebagai pengganti kata kunci kontrol alur `return;`.
  3. Malformasi format string pada makro `println!(":?", ...)` yang tidak memiliki placeholder `{}`.
- **Mekanisme Penyelesaian:**
  1. Tambahkan titik koma: `let key = String::from("CSUCKS");`.
  2. Gunakan kata kunci resmi: `return;`.
  3. Perbaiki pemformatan makro menjadi `println!("{}", ...);`.
  4. Kompilasi dan eksekusi via `cargo run` menghasilkan token: `academy{4r3_y0u_4_ru$t4c30n_n0w?}`.
- **Remediasi Defensif:**
  Gunakan toolchain otomatisasi seperti `rustfmt` dan `clippy` dalam pipeline CI/CD untuk menangkap inkonsistensi pemformatan dan galat sintaksis sebelum kode mencapai tahap integrasi.

#### Modul 3: Challenge 460 - RED (Forensics)
- **Akar Kerentanan (CWE-312 & CWE-530):**
  Penyisipan muatan rahasia pada domain spasial citra digital (LSB) tanpa proteksi kriptografis, serta penyertaan petunjuk operasional di dalam metadata teks publik (chunk `tEXt`) yang memuat puisi akrostik "CHECK LSB".
- **Mekanisme Penyelesaian:**
  1. Ekstraksi chunk `tEXt` mengungkap akrostik huruf awal: **C-H-E-C-K-L-S-B**.
  2. Dekompresi stream zlib pada chunk `IDAT` dan jalankan algoritma defiltering per-scanline (RFC 2083) untuk merekonstruksi matriks piksel RGBA $128 \times 128$.
  3. Ekstraksi bit terendah (LSB) secara berurutan dari kanal R, G, B, dan A.
  4. Penggabungan bit menghasilkan string Base64: `YWNhZGVteXtyM2RfMXNfdGgzX3VsdDFtNHQzX2N1cjNfZjByXzU0ZG4zNTVffQ==`.
  5. Pendekodean Base64 menghasilkan flag resmi: `academy{r3d_1s_th3_ult1m4t3_cur3_f0r_54dn355_}`.
- **Remediasi Defensif:**
  Lakukan sanitasi berkas multimedia secara berkala sebelum dipublikasikan ke domain publik dengan menghapus seluruh segmen metadata opsional (`exiftool -all=`). Terapkan analisis statistik chi-square dan deteksi variansi histogram pada sistem gerbang data (*Content Disarm and Reconstruction / CDR*) untuk mengidentifikasi keberadaan manipulasi bit LSB tersembunyi.
