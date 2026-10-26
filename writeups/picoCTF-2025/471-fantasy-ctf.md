# Writeup: FANTASY CTF (Challenge ID: 471)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Interactive CLI & Competition Rules Scope
- **Difficulty:** Easy
- **Author:** picoCTF Team
- **Event:** picoCTF 2025
- **Points:** 10
- **Flag:** `academy{m1113n1um_3d1710n_07462474}`

---

## Problem Statement & Scope
Tantangan ini menyajikan sebuah simulasi interaktif fiksi ilmiah berbasis antarmuka baris perintah (CLI). Pemain mengikuti narasi karakter bernama Eibhilin dan pendamping AI-nya, Nyx, dalam proses pendaftaran kompetisi picoCTF edisi masa depan. Melalui serangkaian dialog dan pilihan berganda, pemain dituntut memahami aturan dasar kompetisi keamanan siber etis dan mengekstrak flag dari hasil simulasi game.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Etika Kompetisi dan Rules of Engagement (RoE):**
   Dalam kompetisi keamanan siber resmi (seperti picoCTF atau LKS Cyber Security), aturan keterlibatan (*Rules of Engagement*) membatasi tindakan yang diperbolehkan:
   - Satu akun privat per peserta/tim (melarang pendaftaran multi-akun untuk memanipulasi skor).
   - Larangan pembagian flag (*flag sharing*) atau artefak tantangan kepada pihak luar selama kompetisi berlangsung.
   - Larangan menyerang infrastruktur kompetisi di luar target lab yang ditentukan.
2. **Automasi Interaksi Berbasis Socket:** Tantangan CLI interaktif sering kali membutuhkan penanganan aliran teks (stream) dan prompt respon otomatis untuk menavigasi percabangan logika tanpa hambatan latensi manusia.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Luncurkan instance lab container pada endpoint API:
   `PUT /api/challenges/471/instance/`
2. Hubungkan ke layanan melalui netcat:
   ```bash
   nc xebec.cylabacademy.net 42582
   ```
3. Navigasikan dialog simulasi:
   - Tekan `Enter` pada setiap prompt jeda narasi `(Press Enter to continue...)`.
   - Pada pilihan pendaftaran akun, pilih opsi `c` (*Register a single, private account*) atau opsi yang sesuai aturan etis.
   - Pada pilihan sanity challenge, pilih opsi `a` (*Play the game*).
4. Biarkan simulasi menyelesaikan proses bar kemajuan (*progress bar*).
5. Pada akhir dialog, AI pendamping Nyx memberikan flag resmi:
   `academy{m1113n1um_3d1710n_07462474}`.

---

## Flag & Verifikasi
- **Flag:** `academy{m1113n1um_3d1710n_07462474}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Integritas Kompetisi dan Kepatuhan Kebijakan:** Pada ajang kompetisi resmi seperti LKS Cyber Security, pemahaman mendalam terhadap regulasi teknis mencegah diskualifikasi akibat pelanggaran administratif yang tidak disengaja.
- **Validasi Alur Kerja Operator CLI:** Pembuatan skrip otomasi menggunakan modul socket Python memberikan keunggulan kecepatan dalam melakukan parsing log dan eksekusi instruksi terkontrol di terminal Linux.
