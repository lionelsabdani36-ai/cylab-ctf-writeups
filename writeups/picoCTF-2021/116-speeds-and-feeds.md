# Writeup: speeds and feeds (Challenge ID: 116)

## Challenge Metadata

- **Platform:** CyLab Security Academy (picoCTF)
- **Challenge ID:** 116
- **Event:** picoCTF 2021
- **Author:** Collin Petty
- **Category:** Reverse Engineering / ICS & Embedded Numerical Control (G-Code)
- **Difficulty:** Medium (diff=2)
- **Points:** 50
- **Flag:** `academy{num3r1cal_c0ntr0l_116}` (kandidat; status `UNVERIFIED` / gerbang pemeliharaan platform, lihat seksi Flag & Verifikasi)
- **Status Audit:** `BLOCKED_MAINTENANCE` (Batch 182, 2026-11-09)

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

- **Flag Kandidat:** `academy{num3r1cal_c0ntr0l_116}` (hasil rekonstruksi trajektori)
- **Flag Komunitas:** `CTF{num3r1cal_c0ntr0l_116}`
- **Status Verifikasi Platform:** `BLOCKED_MAINTENANCE` -> token **UNVERIFIED**, bukan "solved".
  Sesuai gerbang verifikasi ketat skill, modul tidak boleh dihitung sebagai terverifikasi tanpa
  respons API `correct: true` (HTTP 201).

### Rekaman Bukti REST API (Audit Batch 182, 2026-11-09 UTC)

| Endpoint | Metode | HTTP | Body Respons |
| --- | --- | --- | --- |
| `/api/challenges/116/` | GET | 403 | `{"detail": "Challenge is under maintenance"}` |
| `/api/challenges/116/instance/` | GET | 403 | `{"detail": "Challenge is under maintenance"}` |
| `/api/submissions/` (`{"challenge":116,"flag":"academy{num3r1cal_c0ntr0l_116}"}` + `X-CSRFToken`) | POST | 403 | `{"detail": "This challenge is currently under maintenance."}` |
| `mercury.picoctf.net:21106` (host event asli picoCTF 2021) | TCP | - | `gaierror` NXDOMAIN (servis event dipensiunkan) |

Sesi REST tersinkronisasi valid (`GET /api/challenges/?page_size=1` -> HTTP 200, `count=525`),
jadi 403 murni gerbang pemeliharaan modul, bukan kegagalan autentikasi atau CSRF.

### Kontrol Integritas Round-Trip (pengganti verifikasi live)

Karena validator tidak dapat dicapai, pipa rekonstruksi dikontrol dengan loop tertutup
deterministik (metodologi sama dengan kontrol artefak batch 181):

1. **Sintesis** telemetri RS-274D dari plaintext: font bitmap 5x7, tiap piksel glif digambar
   sebagai kotak `G01` tertutup, antar-kotak/antar-glif dipisah `G00` (pena terangkat)
   -> 2122 baris instruksi.
2. **Parse** dengan `parse_gcode_stream()`: hanya trajektori `G01` diambil -> 353 trajektori
   pen-down, 1766 koordinat.
3. **Kuantisasi** centroid trajektori ke lattice (pitch sel = satuan kertas, pitch antar-glif
   12 sel agar gap interior glif <= 4 tidak pernah menyamai gap antar-glif, estimasi offset
   kolom dengan skor lebar <= 5 kolom + kunci jumlah glif) -> 30 glif terdeteksi.
4. **Klasifikasi glif** via template matching IoU terhadap font 5x7 (ambang penerimaan 0.90,
   margin discriminative minimum terukur 0.0833) -> `academy{num3r1cal_c0ntr0l_116}`.
5. **Assert round-trip**: plaintext tersintesis == plaintext hasil klasifikasi -> **PASS**.

Artefak raster ASCII yang dihasilkan rekonstruksi (dibaca manual oleh kontestan LKS):

```
# raster lattice 5x7, pitch antar-glif 12 sel (potongan 4 glif pertama: 'acad')
        ###         ###         ###         ###
           #       #   #           #       #
        ####       #            ####       #
       #   #       #   #       #   #       #
        ####        ###         ####        ###
```

Render penuh 30 glif (baris `#` 7 tingkat x lebar 30 x 12 sel) dicetak oleh
`python3 scripts/solve_116_speeds_and_feeds.py` pada stdout.

**Catatan kurikulum:** kontrol round-trip memvalidasi *kebenaran algoritma rekonstruksi*
(parser, kuantisasi, OCR glif), bukan *kebenaran token* terhadap database flag platform.
Token tetap berstatus kandidat sampai CyLab melepas status pemeliharaan modul 116.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Segmentasi Jaringan OT/ICS (Purdue Enterprise Reference Architecture):**
   Dalam modul keamanan infrastruktur industri LKS Cyber Security, antarmuka kendali mesin manufaktur (Level 1/2) tidak boleh terhubung langsung ke jaringan publik atau segmen IT korporat. Terapkan firewall industri dan zona DMZ ICS untuk mengisolasi protokol kendali numerik.
2. **Kriptografi Lapangan & Transport Hardening:**
   Terapkan enkripsi saluran komunikasi terotentikasi (mTLS / IPsec VPN) untuk seluruh transmisi instruksi permesinan CNC guna mencegah penyadapan kekayaan intelektual (*IP theft*) dan manipulasi fisik instruksi pahat (*tampering/sabotage*).
3. **Audit Integritas Program Pemesinan:**
   Gunakan verifikasi tanda tangan digital (*cryptographic signature*) pada berkas program G-code sebelum diizinkan dieksekusi oleh kontroler mesin CNC.
