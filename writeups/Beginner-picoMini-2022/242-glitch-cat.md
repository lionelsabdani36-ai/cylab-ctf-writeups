# Writeup: Glitch Cat (Challenge ID: 242)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Socket Automation & Python ASCII Expression Evaluation
- **Difficulty:** Easy (diff=1)
- **Event:** Beginner picoMini 2022
- **Points:** 30
- **Author:** LT 'syreal' Jones
- **Flag:** `academy{gl17ch_m3_n07_3881dce3}`

---

## Problem Statement & Scope
Layanan pencetak token pada endpoint jaringan TCP socket mengalami anomali output (*glitching*) dan mentransmisikan token bendera yang terpecah menjadi sintaksis ekspresi konkatenasi string Python disertai pemanggilan fungsi konversi kode karakter ASCII heksadesimal `chr(0x..)`. Peserta diarahkan untuk mengamati transmisi stream data mentah, mengekstrak representasi nilai kode ordinal karakter ASCII, merekonstruksi string bendera lengkap, dan memverifikasi token pada sistem penilaian.

Ruang lingkup audit keamanan protokol jaringan dan penanganan data input/output mencakup:
1. Analisis arsitektur komunikasi layanan soket TCP (RFC 9293) dan penanganan format output string sintetis.
2. Evaluasi risiko keamanan terkait parsing ekspresi string dan pencegahan penggunaan `eval()` sembarangan (*Safe Expression Evaluation* / CWE-116 & CWE-95).
3. Pemetaan nilai ordinal heksadesimal ke karakter ASCII standar (ISO/IEC 646 / RFC 20).
4. Validasi matriks wrapper bendera resmi pada REST API CyLab Security Academy (`POST /api/submissions/`) sesuai standar **NIST SP 800-115 Section 4.2** (*Network Protocol Analysis and Verification Testing*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyandian Karakter ASCII dan Representasi Heksadesimal (RFC 20):**
   - Karakter dalam komunikasi digital direpresentasikan sebagai nilai numerik dalam tabel ASCII (*American Standard Code for Information Interchange*).
   - Fungsi bawaan Python `chr(i)` menerima bilangan bulat `i` (dalam basis 10 atau basis 16) dan mengembalikan karakter string yang bersesuaian.
   - Pada layanan `Glitch Cat`, token bendera dikirimkan dalam format ekspresi sintaksis Python:
     ```python
     'academy{gl17ch_m3_n07_' + chr(0x33) + chr(0x38) + chr(0x38) + chr(0x31) + chr(0x64) + chr(0x63) + chr(0x65) + chr(0x33) + '}'
     ```
   - Pemetaan nilai heksadesimal ke karakter ASCII:
     - `0x33` (desimal 51) berkorespondensi dengan karakter `'3'`
     - `0x38` (desimal 56) berkorespondensi dengan karakter `'8'`
     - `0x38` (desimal 56) berkorespondensi dengan karakter `'8'`
     - `0x31` (desimal 49) berkorespondensi dengan karakter `'1'`
     - `0x64` (desimal 100) berkorespondensi dengan karakter `'d'`
     - `0x63` (desimal 99) berkorespondensi dengan karakter `'c'`
     - `0x65` (desimal 101) berkorespondensi dengan karakter `'e'`
     - `0x33` (desimal 51) berkorespondensi dengan karakter `'3'`
     Penggabungan seluruh fragmen menghasilkan akhiran: `3881dce3`.
2. **Kerapuhan Penanganan Output dan Risiko Eksekusi Kode Klien (CWE-116 / CWE-95):**
   - Mengirimkan data keluaran yang diformat sebagai kode sumber bahasa pemrograman (*executable expression*) menciptakan jebakan bagi pengembang klien yang naif.
   - Apabila aplikasi penerima mengevaluasi string jaringan tersebut secara langsung menggunakan interpreter dinamis seperti `eval()` di Python atau JavaScript, penyerang yang berhasil menyusup atau memanipulasi lalu lintas jaringan (Man-in-the-Middle) dapat menyuntikkan muatan kode berbahaya untuk memicu *Remote Code Execution* (RCE) pada mesin klien.
   - Solusi yang aman (*defensive parsing*) wajib menggunakan ekstraksi berbasis ekspresi reguler (*regex*) atau parser berbasis AST yang aman (*safe parsing*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pemeriksaan Interaktif Jaringan:**
   - Menghubungkan soket TCP ke kontainer lab interaktif menggunakan utilitas `nc` (*netcat*) atau skrip Python:
     ```bash
     nc chatelaine.cylabacademy.net <port>
     ```
   - Server membalas dengan string transmisi:
     ```text
     'academy{gl17ch_m3_n07_' + chr(0x33) + chr(0x38) + chr(0x38) + chr(0x31) + chr(0x64) + chr(0x63) + chr(0x65) + chr(0x33) + '}'
     ```
2. **Ekstraksi Deterministik Aman (Zero `eval()`):**
   - Menggunakan ekspresi reguler Python untuk mengekstrak setiap argumen di dalam fungsi `chr(...)`:
     ```python
     chr_matches = re.findall(r"chr\((0x[0-9a-fA-F]+|\d+)\)", raw_text)
     suffix = "".join([chr(int(x, 0)) for x in chr_matches])
     ```
   - Merekonstruksi string lengkap:
     `academy{gl17ch_m3_n07_3881dce3}`.
3. **Penyusunan Skrip Solver Reproduktif:**
   - Menyusun skrip `scripts/solve_242_glitch_cat.py` yang mendukung penanganan soket dinamis maupun evaluasi deterministik offline, dilengkapi dengan verifikasi live ke CyLab API.
4. **Validasi Matriks Wrapper Bendera:**
   - Melakukan pengujian kirim live via `POST /api/submissions/`:
     - Uji wrapper native CyLab `academy{gl17ch_m3_n07_3881dce3}`: **HTTP 201 Created (`correct: true`)**.
     - Uji wrapper event `picoCTF{gl17ch_m3_n07_3881dce3}`: **HTTP 201 Created (`correct: false`)**.
   - Validator CyLab pada event `Beginner picoMini 2022` secara ketat menerima format `academy{...}` dan menolak `picoCTF{...}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{gl17ch_m3_n07_3881dce3}`
- **Status Live:** **SOLVED (HTTP 201 Created, correct: true)**
- **Verifikasi Skrip:** `python3 scripts/solve_242_glitch_cat.py` berhasil tuntas dengan status exit 0.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Penguasaan Dasar Representasi Data Biner dan Karakter (General Skills & Forensics):**
   - Dalam kompetisi LKS Cyber Security, kecepatan dan ketepatan melakukan konversi representasi data (heksadesimal, desimal, oktal, ASCII, Unicode) adalah keterampilan fundamental yang diuji di berbagai modul, mulai dari analisis lalu lintas jaringan (PCAP) hingga analisis artefak memori.
2. **Prinsip Sanitasi Parsing pada Aplikasi Klien (Defensive Coding):**
   - Hindari secara mutlak penggunaan fungsi evaluasi dinamis seperti `eval()` atau `exec()` untuk mengurai payload dari jaringan yang tidak terpercaya.
   - Terapkan skema serialisasi data standar seperti JSON atau Protocol Buffers untuk pertukaran pesan antar layanan, sehingga data dan kode terpisah secara tegas.
3. **Penerapan Pengujian Validasi Protokol:**
   - Terapkan validasi skema pesan ketat pada lapisan ingress aplikasi untuk memastikan setiap paket data mematuhi struktur yang diharapkan sebelum diproses oleh modul aplikasi tingkat lanjut.
