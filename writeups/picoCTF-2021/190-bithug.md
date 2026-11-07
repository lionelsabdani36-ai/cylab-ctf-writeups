# Writeup: Bithug (Challenge ID: 190)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / SSRF & Git Internal Protocol Smuggling
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 500
- **Author:** Collin Petty
- **Flag:** `academy{good_job_at_gitting_good}`

---

## Problem Statement & Scope
Tantangan `Bithug` menghadirkan sebuah aplikasi web pengelolaan kode sumber git (*source code management*) mandiri yang dirancang sebagai alternatif ringan untuk platform git modern. Aplikasi ini dibangun menggunakan Node.js/Express di sisi backend serta React di sisi frontend. Setiap pengguna yang mendaftar memiliki ruang repositori tersendiri, kemampuan untuk mengonfigurasi *webhooks*, serta mengelola hak akses kolaborator.

Bendera rahasia (*flag*) tersimpan di dalam repositori privat yang hanya dapat diakses secara lokal oleh sistem internal pada jalur `_/<username>.git`. Berkas `README.md` pada repositori tersebut memuat string flag target. Pengguna luar tidak memiliki izin untuk mengkloning atau membaca repositori ini secara langsung.

Ruang lingkup audit keamanan aplikasi dan pengujian penetrasi ini mencakup:
1. Pemetaan arsitektur aplikasi web fullstack dan mekanisme otentikasi/otorisasi kontrol akses repositori.
2. Analisis alur validasi dan pengiriman webhook pada event `git push`.
3. Eksploitasi kerentanan *Server-Side Request Forgery* (SSRF) untuk menjangkau port loopback internal `127.0.0.1:1823`.
4. Penyelundupan instruksi protokol Git atau manipulasi API kolaborator untuk mendapatkan akses baca ke repositori rahasia.
5. Verifikasi kepatuhan pengujian keamanan berbasis standar **NIST SP 800-115 Section 4.2 & 4.3** (*Target Identification and Vulnerability Scanning / Web Application Testing*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Server-Side Request Forgery pada Webhook Dispatcher (CWE-918)
Fitur webhook memungkinkan pemilik repositori menentukan URL eksternal yang akan menerima notifikasi HTTP POST setiap kali terjadi aktivitas `push`. Namun, implementasi pengiriman webhook pada backend tidak memvalidasi alamat tujuan terhadap rentang IP privat atau antarmuka loopback (`127.0.0.1`, `localhost`, `::1`). Hal ini memungkinkan pengguna memasukkan alamat lokal server sebagai endpoint webhook.

### 2. Bypass Kontrol Akses melalui Jalur Internal Tepercaya (CWE-285)
Layanan internal Git (`git-upload-pack` dan REST API administratif) berjalan pada port lokal tanpa proteksi otentikasi tambahan karena mengasumsikan seluruh request yang berasal dari antarmuka loopback adalah aman (*blind trust of localhost traffic*). Dengan mengarahkan payload webhook ke `http://127.0.0.1:1823/_/<username>.git`, permintaan HTTP dari webhook dieksekusi dengan privilege lokal, mengizinkan penambahan pengguna penyerang sebagai kolaborator repositori rahasia.

---

## Tahapan Eksploitasi & Verifikasi (Reproduction Steps)

1. **Pendaftaran Akun & Pembuatan Repositori Target:**
   - Mendaftarkan akun penyerang pada antarmuka web BitHug.
   - Membuat sebuah repositori publik baru (misalnya `attacker/repo`).

2. **Konfigurasi Webhook SSRF:**
   - Menambahkan webhook baru pada repositori `attacker/repo`.
   - Mengatur URL webhook mengarah ke endpoint API lokal internal:
     `http://127.0.0.1:1823/_/attacker.git/collaborators` atau memanfaatkan parameter git-upload-pack loopback.

3. **Pemicuan Event Git Push:**
   - Melakukan inisialisasi lokal, menambahkan berkas komit, dan mengeksekusi perintah `git push` ke `attacker/repo`.
   - Server BitHug menerima push, kemudian secara otomatis menembakkan request webhook HTTP POST internal ke endpoint loopback yang telah ditentukan.

4. **Ekstraksi Flag:**
   - Melalui request webhook internal, hak akses repositori `_/attacker.git` terbuka.
   - Mengkloning repositori privat atau membuka tampilan web untuk berkas `README.md` pada repositori `_/attacker.git`.
   - Membaca isi flag yang terungkap: `academy{good_job_at_gitting_good}`.

---

## Rekomendasi Mitigasi & Pengerasan Keamanan (Remediation)
1. **Penerapan Validasi Ketat pada Webhook / URL Whitelisting (NIST SP 800-53 SC-7):**
   - Batasi pengiriman request webhook hanya ke domain publik yang valid.
   - Blokir seluruh rentang alamat privat RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), antarmuka loopback (`127.0.0.0/8`), dan *link-local* metadata cloud (`169.254.169.254`).
2. **Prinsip Zero Trust pada Antarmuka Jaringan Internal (NIST SP 800-207):**
   - Layanan internal dan daemon Git lokal wajib menerapkan otentikasi token atau mTLS yang ketat bahkan untuk koneksi dari `127.0.0.1`.
3. **Isolasi Lingkungan Pengiriman Webhook (Egress Sandboxing):**
   - Jalankan pekerja (*worker*) pengirim webhook di dalam container/DMZ terisolasi tanpa akses rute langsung ke jaringan internal aplikasi.

---

## Script Reproduksi
Script solver mandiri tersedia pada berkas `scripts/solve_190_bithug.py`.
Jalankan verifikasi dengan perintah:
```bash
python3 scripts/solve_190_bithug.py
```
Hasil verifikasi mengembalikan token flag valid:
`academy{good_job_at_gitting_good}`
