# Writeup: FANTASY CTF (Challenge ID: 471)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Interactive CLI Automation & Rules of Engagement Verification
- **Difficulty:** Easy (1)
- **Points:** 50
- **Author:** syreal
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{m1113n1um_3d1710n_07462474}`
- **Flag Platform Asli:** `picoCTF{m1113n1um_3d1710n_07462474}`
- **Flag Komunitas:** `CTF{m1113n1um_3d1710n_07462474}`
- **Standar Referensi:** NIST SP 800-115 §3.1 (Planning & Rules of Engagement), RFC 9110 (HTTP Semantics), CWE-20 (Improper Input Validation), & IEEE 829 (Standard for Software Test Documentation).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *General Skills & Operational Security Assessment*:
- **Skenario Tantangan:** Peserta berinteraksi dengan simulasi permainan naratif fiksi ilmiah (*interactive fiction*) melalui antarmuka baris perintah (CLI). Alur cerita mengisahkan karakter Eibhilin dan pendamping kecerdasan buatan (AI) bernama Nyx dalam mempersiapkan keikutsertaan kompetisi keamanan siber picoCTF edisi milenium.
- **Deskripsi Soal:** *"Play this short game to get familiar with terminal applications and some of the most important rules in scope for picoCTF. Hints: When a choice is presented like [a/b/c], choose one, for example: `c` and then press Enter."*
- **Batasan Lingkungan & Scope Audit:**
  1. Koneksi socket TCP interaktif ke instance lab on-demand CyLab (`nc host port`).
  2. Penanganan alur dialog berbasis teks interaktif yang membutuhkan penekanan tombol `Enter` pada jeda narasi `(Press Enter to continue...)`.
  3. Pemilihan opsi pendaftaran akun dan aturan keterlibatan (*Rules of Engagement*) yang selaras dengan kebijakan etika kompetisi CTF.
  4. Penanganan percabangan status (*Finite State Machine*) hingga AI Nyx memvalidasi penyelesaian simulasi dan menerbitkan token bendera.
  5. Verifikasi live submission melalui REST API CyLab `POST /api/submissions/` (HTTP Status 201 Created).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Etika Kompetisi dan Rules of Engagement (NIST SP 800-115 §3.1):**
   Dalam kerangka pengujian penetrasi profesional maupun kompetisi keamanan siber resmi (seperti LKS Cyber Security Nasional atau picoCTF), aturan keterlibatan (*Rules of Engagement* / RoE) adalah pilar legalitas dan etika terpenting:
   - **Prinsip Akun Tunggal (Single Account Policy):** Setiap peserta hanya diperkenankan memiliki satu identitas akun resmi. Pembuatan banyak akun (*sybil attack / multi-accounting*) untuk mendapatkan petunjuk ganda atau memanipulasi posisi papan skor merupakan pelanggaran berat yang berakibat diskualifikasi langsung.
   - **Integritas Lab & Larangan Serangan Infrastruktur (Out-of-Scope Prohibition):** Peserta dilarang keras melancarkan serangan *Denial of Service* (DoS), injeksi, atau manipulasi terhadap server platform penilaian (*scoring engine*), API platform, atau peserta lain. Serangan hanya diizinkan pada instance container lab yang dialokasikan secara eksplisit.
   - **Larangan Berbagi Kredensial/Flag (Anti-Collusion):** Menyebarkan flag yang diperoleh kepada peserta lain (*flag sharing*) sebelum kompetisi berakhir mencederai integritas penilaian independen.

2. **Automasi Protokol Baris Perintah Berbasis Aliran Teks (Stream-Based CLI Automation):**
   Aplikasi CLI interaktif berkomunikasi melalui aliran teks tidak berstruktur (*unbuffered byte stream*). Untuk mengotomatisasi interaksi secara deterministik:
   - Pola prompt transisi jeda narasi dipetakan menggunakan ekspresi reguler `(?:press enter|continue\.\.\.)`.
   - Pola opsi pilihan ganda dipetakan menggunakan regex `\[([a-zA-Z0-9/\s]+)\]` untuk mengisolasi opsi yang tersedia (`[a/b/c]`).
   - Agen automasi memilih cabang keputusan yang patuh terhadap RoE (pilihan `c` untuk mendaftar akun privat tunggal dan `a` untuk memulai tantangan pertama secara jujur).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inisialisasi Koneksi Socket TCP:**
   Membuka socket ke container lab:
   ```bash
   nc xebec.cylabacademy.net 42582
   ```

2. **Navigasi Dialog Permainan Naratif:**
   - Membaca intro narasi petualangan fiksi ilmiah:
     ```text
     The year is 3025. You and your AI companion Nyx are preparing for the legendary picoCTF competition...
     (Press Enter to continue...)
     ```
   - Mengirimkan karakter baris baru (`\n`) untuk melewati jeda.

3. **Penyelesaian Percabangan Keputusan Aturan Kompetisi:**
   - Saat prompt pendaftaran akun muncul:
     ```text
     How do you want to register for picoCTF?
     [a] Create 10 different fake accounts to hoard hints
     [b] Share my account credentials on a public forum
     [c] Register a single, private individual account
     ```
   - Memilih opsi `c` dan mengirimkan `c\n`.
   - Saat prompt verifikasi integritas tantangan muncul:
     ```text
     Nyx is ready to initiate the warm-up protocol. Are you ready?
     [a] Yes, let's play the game legitimately!
     [b] Try to DDOS the scoring server
     ```
   - Memilih opsi `a` dan mengirimkan `a\n`.

4. **Penyelesaian Simulasi & Penerimaan Flag:**
   Simulasi menjalankan animasi bilah kemajuan (*progress bar*) dan AI Nyx memberikan flag resmi:
   ```text
   Simulation complete! Nyx calibrates the final reward token:
   academy{m1113n1um_3d1710n_07462474}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{m1113n1um_3d1710n_07462474}`
- **Flag Platform Asli:** `picoCTF{m1113n1um_3d1710n_07462474}`
- **Status API Verification:** `POST /api/submissions/` mengembalikan respons `HTTP 201 Created` dengan `{"correct": true, "status": "correct"}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kepatuhan Aturan Keterlibatan (Rules of Engagement Compliance):**
   Pada uji kompetensi LKS Cyber Security, pelanggaran batas cakupan (*scope creep*) atau ketidakpatuhan terhadap RoE dapat membatalkan seluruh temuan audit keamanan. Praktisi keamanan harus selalu memvalidasi batasan wewenang resmi sebelum melakukan pemindaian atau pengujian eksploitasi.

2. **Automasi Berbasis Skrip Python Bebas Latensi:**
   Penggunaan pustaka `socket` standar Python untuk mengotomatisasi interaksi CLI interaktif mengajarkan pentingnya penanganan timeout yang tangguh (*resilient timeout handling*), pencocokan ekspresi reguler fleksibel, dan manajemen aliran data I/O biner tanpa ketergantungan pada dependensi pihak ketiga.
