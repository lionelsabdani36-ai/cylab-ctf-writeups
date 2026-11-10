# Writeup: Nothing Up My Sleeve (Challenge ID: 91)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Network Asset Retrieval & Integrity Verification
- **Difficulty:** Medium (Diff: 2)
- **Author:** Q0h313th
- **Event:** picoCTF 2020 Mini-Competition
- **Points:** 1
- **Flag:** `academy{c0ngr4ts_0n_y0ur_s4n1ty}`

---

## Problem Statement & Scope

Tantangan menguji kesiapan konektivitas jaringan, protokol pengambilan aset biner berbasis CLI (*Command Line Interface*), dan verifikasi integritas data (*cryptographic hashing*). Penulis tantangan menegaskan bahwa flag berada dalam kondisi terbuka (*in-the-clear*) pada berkas `flag.txt` yang dihosting di jaringan pengiriman konten (*Content Delivery Network* / CDN) CyLab Academy.

Batasan audit operasional:
1. Lokasi aset target: `https://challenge-files.cylabacademy.net/library/d8535ec63bf7b81b424ec33b24afe9e52d234899be8bf61ae85206453ff8e62b/flag.txt`.
2. Pengambilan aset dilakukan tanpa bantuan peramban grafis (*headless environment*) menggunakan utilitas transfer jaringan standar (`curl` atau `wget`).
3. Verifikasi mencakup pemeriksaan integritas menggunakan ringkasan kriptografis SHA-256 (RFC 6234).
4. Penilaian kepatuhan merujuk pada standar NIST SP 800-115 Section 4.2 (*Target Identification and Network Reconnaissance*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Paparan Data Terbuka / Cleartext Secret Storage (CWE-319 & CWE-200)
Akar masalah dalam skenario ini adalah penyimpanan rahasia sensitif dalam format teks polos (*plaintext*) pada lokasi penyimpanan objek yang dapat diakses publik (*publicly accessible bucket/CDN*). Siapa pun yang memiliki URI spesifik dapat mengunduh dan membaca informasi sensitif tanpa melewati mekanisme autentikasi maupun otorisasi peran (*Role-Based Access Control*).

### 2. Semantika Transport HTTP/1.1 & TLS (RFC 9110 & RFC 2818)
Protokol HTTPS melindungi kerahasiaan data dalam transit (*data-in-transit*) dari serangan *eavesdropping* atau *Man-in-the-Middle* (MitM) di sepanjang rute jaringan ISP/gateway. Namun, TLS tidak melindungi data di tingkat aplikasi jika artefak itu sendiri sengaja diekspos sebagai objek publik tanpa kontrol akses (*access control lists / pre-signed URLs*).

### 3. Validasi Integritas Kriptografis (RFC 6234)
Dalam pengujian penetrasi dan incident response, setiap berkas yang diunduh dari jaringan eksternal wajib diverifikasi menggunakan fungsi *secure cryptographic hash* (seperti SHA-256) untuk memastikan berkas tidak rusak (*corruption*) atau dimanipulasi oleh pihak ketiga (*tampering*):
$$\text{SHA-256}(\text{flag.txt}) = \text{ebf2774283940b9a69962376466e18a84efee6daa9cb8feb8d325b67254205dd}$$

---

## Rekonstruksi Eksploitasi Step-by-Step

### 1. Pengunduhan Berkas Target via CLI
Eksekusi pengambilan artefak menggunakan `curl` dengan flag penyimpanan `-sL` (silent, ikuti redirect HTTP):
```bash
curl -sL "https://challenge-files.cylabacademy.net/library/d8535ec63bf7b81b424ec33b24afe9e52d234899be8bf61ae85206453ff8e62b/flag.txt" -o flag.txt
```
Atau menggunakan `wget`:
```bash
wget -q "https://challenge-files.cylabacademy.net/library/d8535ec63bf7b81b424ec33b24afe9e52d234899be8bf61ae85206453ff8e62b/flag.txt"
```

### 2. Validasi Ukuran dan Hash Integritas SHA-256
Periksa ringkasan hash SHA-256 dari berkas hasil unduhan:
```bash
sha256sum flag.txt
# Hasil: ebf2774283940b9a69962376466e18a84efee6daa9cb8feb8d325b67254205dd  flag.txt
```
Ukuran berkas terkonfirmasi tepat 32 byte.

### 3. Pembacaan Token Teks Polos
Baca konten berkas menggunakan perintah `cat`:
```bash
cat flag.txt
# Hasil: academy{c0ngr4ts_0n_y0ur_s4n1ty}
```

---

## Flag & Verifikasi

- **Flag Terverifikasi:** `academy{c0ngr4ts_0n_y0ur_s4n1ty}`
- **Status API Platform:** Live HTTP 201 Created via `POST /api/submissions/` dengan respons resmi `{"correct": true}`.
- **Validasi Wrapper:** Platform CyLab menerima wrapper native `academy{...}` dan menolak varian legacy `picoCTF{...}` (`correct: false`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Kompetensi Modul Fundamental & Jaringan LKS Cyber Security
- **Asset Acquisition Hygiene:** Peserta LKS harus terbiasa mendokumentasikan nilai hash setiap kali mengunduh berkas bukti forensik atau artefak tantangan guna menjaga integritas barang bukti (*chain of custody*).
- **Automated Scripting:** Kemampuan menulis skrip otomasi satu baris (`curl` dipadukan dengan `sha256sum` dan `grep`) memangkas waktu kerja manual secara signifikan saat menghadapi puluhan aset.

### 2. Remediasi Defensif & Keamanan Cloud Storage
- **Restricted Bucket Policies:** Pastikan seluruh bucket penyimpanan cloud (AWS S3, Google Cloud Storage, Azure Blob) memiliki konfigurasi `Block Public Access` aktif secara default untuk mencegah kebocoran data rahasia.
- **Pre-signed URL dengan Waktu Kedaluwarsa:** Bila berkas harus dibagikan kepada pengguna terotentikasi, gunakan URL terotentikasi dengan masa kedaluwarsa singkat (*time-limited pre-signed URLs*) alih-alih tautan statis permanen.
- **Enkripsi Data at Rest (CWE-311):** Enkripsi seluruh artefak sensitif pada lapisan penyimpanan menggunakan kunci yang dikelola layanan manajemen kunci (*KMS / Key Management Service*).
