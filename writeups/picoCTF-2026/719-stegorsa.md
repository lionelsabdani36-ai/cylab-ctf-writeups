# Writeup: StegoRSA (Challenge ID: 719)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Steganography & RSA Private Key Extraction
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** picoCTF
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{rs4_k3y_1n_1mg_21d0a083}`
- **Flag Komunitas:** `CTF{rs4_k3y_1n_1mg_21d0a083}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 8017 (PKCS #1 v2.2: RSA Cryptography Standard), CWE-312 (Cleartext Storage of Sensitive Information), & JPEG Metadata / EXIF / COM Segment Specifications.

---

## Problem Statement & Scope

Pada modul bimbingan teknis persiapan lomba LKS `StegoRSA`, peserta diuji dalam menghubungkan analisis forensik steganografi berkas citra digital dengan pemulihan kunci kriptografi asimetris RSA:
- Skenario lingkungan: Diberikan dua berkas artefak:
  1. Citra grafis format JPEG: `image.jpg` (~20 KB).
  2. Berkas terenkripsi biner: `flag.enc` (256 byte, RSA-2048 ciphertext).
- Pernyataan tantangan:
  > *"A message has been encrypted using RSA. The public key is gone... but someone might have been careless with the private key. Can you recover it and decrypt the message?"*
- Petunjuk resmi investigasi:
  1. *"Metadata can tell you more than you expect."*
  2. *"Hex can be turned back into a key file."*
- Sasaran pengujian: Memindai struktur biner citra JPEG untuk mengekstrak string heksadesimal tersembunyi, merekonstruksi kunci privat RSA format PEM (Privacy Enhanced Mail), mendekripsi ciphertext `flag.enc` menggunakan skema PKCS#1 v1.5, dan memvalidasi token resmi pada endpoint REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Kontainer JPEG & Penyisipan Metadata Tidak Aman (CWE-312):**
   Format berkas citra JPEG (JFIF) tersusun atas segmen penanda (*markers*) yang diawali dengan byte `0xFF` diikuti oleh kode byte pengidentifikasi segmen (seperti `0xFFE0` untuk APP0, `0xFFE1` untuk EXIF, dan `0xFFFE` untuk komentar COM).
   Pengembang atau pengguna yang ceroboh seringkali menyematkan data sensitif (seperti kredensial atau kunci privat) ke dalam segmen metadata citra atau di akhir payload citra (*appended bytes*). Walaupun data tersebut dienkode dalam bentuk heksadesimal, penyandian berbasis hex bukanlah enkripsi kriptografis dan dapat diekstrak secara deterministik.

2. **Karakteristik Tanda Tangan Kunci Privat RSA Format PEM:**
   Kunci privat RSA yang diserialisasi dalam format PEM memiliki header dan footer ASCII yang baku:
   `-----BEGIN PRIVATE KEY-----` (atau `-----BEGIN RSA PRIVATE KEY-----`).
   Dalam representasi biner heksadesimal (ASCII-to-hex):
   - Karakter `-` memiliki kode heksadesimal `2D`.
   - Pola lima tanda hubung `-----` diwakili oleh byte `2d2d2d2d2d`.
   - String `-----BEGIN PRIVATE KEY` menghasilkan pola heksadesimal khas:
     `2d2d2d2d2d424547494e2050524956415445204b4559...`.
   Pola heksadesimal ini menjadi tanda tangan statis (*signature pattern*) yang sangat mudah diidentifikasi dengan pemindaian ekspresi reguler (*regex scan*) pada byte stream citra.

3. **Prinsip Dekripsi Kriptografi Asimetris RSA (RFC 8017):**
   RSA mengenkripsi pesan $m$ menggunakan kunci publik $(n, e)$ melalui operasi matematika $c \equiv m^e \pmod n$.
   Bila kunci privat $(n, d)$ atau struktur lengkap PEM (yang memuat faktor prima $p, q$, eksponen $d$, serta koefisien CRT $dp, dq, q_{inv}$) berhasil dipulihkan secara utuh, pemulihan pesan teks jelas dapat dilakukan langsung tanpa memerlukan faktorisasi modulus:
   $$m \equiv c^d \pmod n$$
   Dengan menerapkan unpadding skema PKCS#1 v1.5, pesan asli $m$ dapat dibaca secara langsung.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Biner Citra JPEG & Identifikasi Pola Hex:**
   Membaca dan memindai aliran biner `image.jpg` untuk mendeteksi tanda tangan header PEM ber-encoding hex:
   ```bash
   strings -a image.jpg | grep -E "2d2d2d2d2d4245"
   ```
   Ditemukan satu blok string heksadesimal kontinu berukuran 3.410 karakter:
   `2d2d2d2d2d424547494e2050524956415445204b4559...`

2. **Ekstraksi & Rekonstruksi Kunci Format PEM:**
   Mengekstrak blok heksadesimal dan mengonversinya kembali ke karakter ASCII untuk menghasilkan berkas `recovered_priv.pem`:
   ```python
   import re
   raw_img = open("image.jpg", "rb").read()
   m = re.search(rb"(2d2d2d2d2d424547494e20[0-9a-fA-F]+)", raw_img)
   pem_text = bytes.fromhex(m.group(1).decode("ascii")).decode("utf-8")
   with open("recovered_priv.pem", "w") as f:
       f.write(pem_text)
   ```
   Verifikasi isi kunci privat PEM:
   ```bash
   openssl rsa -in recovered_priv.pem -text -noout
   ```
   Output mengonfirmasi kunci privat valid bertipe RSA 2048-bit lengkap dengan modulus $n$, eksponen $e$, $d$, prima $p, q$, dan koefisien CRT.

3. **Dekripsi Ciphertext `flag.enc` Menggunakan OpenSSL:**
   Mengeksekusi dekripsi asimetris terhadap berkas `flag.enc`:
   ```bash
   openssl pkeyutl -decrypt -inkey recovered_priv.pem -in flag.enc
   ```
   Hasil dekripsi menampilkan string bendera teks jelas:
   `academy{rs4_k3y_1n_1mg_21d0a083}`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{rs4_k3y_1n_1mg_21d0a083}`
- **Flag Komunitas:** `CTF{rs4_k3y_1n_1mg_21d0a083}`
- **Log Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 719,
    "flag": "academy{rs4_k3y_1n_1mg_21d0a083}",
    "correct": true,
    "historical": false
  }
  ```
  Status respons HTTP: `201 Created` mengonfirmasi token valid dan tercatat secara definitif.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Rekomendasi Remediasi & Hardening (Defensive Perspective):**
   - **Pemisahan Penyimpanan Kunci (Hardware Security Module / KMS):** Kunci privat kriptografi tidak boleh disimpan di sistem berkas lokal atau disematkan bersama media konten publik. Kunci harus dikelola menggunakan modul perangkat keras aman (HSM) atau layanan KMS (Key Management Service) yang menerapkan kontrol akses ketat (*least privilege*).
   - **Sanitasi Metadata Media (Stripping EXIF/COM):** Saluran publikasi berkas media publik (web portal, repositori aset) wajib menerapkan pembersihan metadata otomatis menggunakan pustaka seperti `exiftool -all= image.jpg` atau ImageMagick `-strip` sebelum berkas disajikan ke publik.
   - **Pemindaian Rahasia Otomatis (Secret Scanning Pipeline):** Memasang perkakas *secret detection* (Gitleaks, Trufflehog) dalam pipeline CI/CD untuk mencegah terjadinya *accidental commit* kunci privat atau token rahasia ke repositori bersama.

2. **Relevansi Modul LKS Cyber Security:**
   - **Kriptografi Terapan & Manajemen Kunci:** Menguji pemahaman peserta mengenai struktur serialisasi kunci privat (PKCS#1 vs PKCS#8), mekanisme penanganan padding PKCS#1 v1.5, dan eksekusi dekripsi OpenSSL CLI.
   - **Analisis Steganografi & Forensik Berkas:** Memperkuat kemampuan peserta dalam membedah segmen kontainer JPEG dan mengenali tanda tangan heksadesimal (*magic signatures*) dari format standar industri.
