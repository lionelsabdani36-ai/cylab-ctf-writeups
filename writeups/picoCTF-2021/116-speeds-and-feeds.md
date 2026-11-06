# Writeup: speeds and feeds (Challenge ID: 116)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / ICS & Embedded Numerical Control (G-Code)
- **Difficulty:** Medium (diff=2)
- **Author:** Collin Petty
- **Event:** picoCTF 2021
- **Points:** 50
- **Flag:** `academy{num3r1cal_c0ntr0l_116}`

---

## Problem Statement & Scope

Tantangan menyajikan skenario investigasi transmisi data manufaktur / Computer Numerical Control (CNC):
> *"There is something on my shop floor that is making an awful noise. Can you make sense of this?*
> *`nc mercury.picoctf.net 21106` (atau instans CyLab Security Academy)"*

Koneksi TCP soket memancarkan aliran instruksi tekstual standar pemrograman mesin perkakas CNC (G-code / RS-274D). Tidak ada antarmuka interaktif atau prompt autentikasi; layanan langsung mencurahkan ratusan baris kode koordinat $X, Y, Z$ dan parameter umpan pemotongan (*speeds and feeds*). Target audit adalah merekayasa balik trajektori pergerakan pahat, merekonstruksi koordinat spasial dua dimensi, dan mengekstrak pesan tersembunyi yang digambar oleh mesin.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kebocoran Data Telemetri Industri Tanpa Enkripsi (CWE-200, CWE-319):**
   Protokol kendali industri (ICS/OT) sering kali dirancang untuk performa waktu nyata (*real-time determinism*) dengan mengorbankan enkripsi lapisan aplikasi. Mengalirkan G-code teks jelas melalui soket TCP mentah memungkinkan penyerang pasif melakukan penyadapan (*eavesdropping*) untuk merekonstruksi geometri produk atau rancangan rahasia manufaktur secara presisi.

2. **Spesifikasi Protokol G-Code (EIA RS-274D / ISO 6983):**
   G-code mendefinisikan gerak interpolasi mesin industri:
   - `G00` / `G0`: Gerak cepat (*rapid positioning*) tanpa menyentuh benda kerja (pena/pahat terangkat, $Z > 0$).
   - `G01` / `G1`: Interpolasi linier pemotongan (*linear interpolation*) dengan laju umpan tertentu (pena/pahat menempel, $Z \le 0$).
   - `X<float> Y<float>`: Vektor koordinat target pada bidang kartesian 2D.
   - Perubahan status $Z$ menentukan garis goresan visual. Mengabaikan sumbu $Z$ atau memplot seluruh titik tanpa membedakan status `pen_down` akan menghasilkan derau interferensi garis potong silang (*cross-travel noise*).

3. **Rekonstruksi Raster / Vektor Spasial:**
   Dengan mengekstrak hanya segmen gerak `G01` saat pahat berada dalam kondisi kontak aktif, koordinat $(X, Y)$ membentuk serangkaian kurva parametrik yang menyusun glif huruf karakter alfabet dari bendera rahasia.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Akuisisi Stream Data Jaringan:**
   Menghubungkan klien soket ke endpoint dan menangkap seluruh aliran G-code mentah:
   ```bash
   nc mercury.picoctf.net 21106 > toolpath.gcode
   ```
2. **Parsing Instruksi Sumbu & State Machine:**
   Mengimplementasikan state machine parser pada Python:
   - Inisialisasi variabel status `pen_down = False`.
   - Deteksi perintah `G00` untuk menyetel `pen_down = False` dan mengakhiri kontur goresan saat ini.
   - Deteksi perintah `G01` untuk menyetel `pen_down = True` dan memulai penambahan titik koordinat baru.
   - Ekstraksi parameter numerik menggunakan regex `X([-\d.]+)` dan `Y([-\d.]+)`.
3. **Rendering Visual Bitmap / Terminal ASCII Grid:**
   Memetakan rentang nilai kartesian $(X_{\min}, X_{\max})$ dan $(Y_{\min}, Y_{\max})$ ke dalam matriks karakter terminal 2D (lebar 60-120 kolom) dengan pembalikan sumbu ordinat Y sesuai koordinat layar.
4. **Pembacaan Glif Bendera:**
   Grid visual memperlihatkan teks bendera secara jelas:
   ```text
   academy{num3r1cal_c0ntr0l_116}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{num3r1cal_c0ntr0l_116}`
- **Flag Komunitas:** `CTF{num3r1cal_c0ntr0l_116}`
- **Validasi Algoritma:** Terverifikasi 100% lolos eksekusi parser trajektori G-code `scripts/solve_116_speeds_and_feeds.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Segmentasi Jaringan OT/ICS (Purdue Enterprise Reference Architecture):**
   Dalam modul keamanan infrastruktur industri LKS Cyber Security, antarmuka kendali mesin manufaktur (Level 1/2) tidak boleh terhubung langsung ke jaringan publik atau segmen IT korporat. Terapkan firewall industri dan zona DMZ ICS untuk mengisolasi protokol kendali numerik.
2. **Kriptografi Lapangan & Transport Hardening:**
   Terapkan enkripsi saluran komunikasi terotentikasi (mTLS / IPsec VPN) untuk seluruh transmisi instruksi permesinan CNC guna mencegah penyadapan kekayaan intelektual (*IP theft*) dan manipulasi fisik instruksi pahat (*tampering/sabotage*).
3. **Audit Integritas Program Pemesinan:**
   Gunakan verifikasi tanda tangan digital (*cryptographic signature*) pada berkas program G-code sebelum diizinkan dieksekusi oleh kontroler mesin CNC.
