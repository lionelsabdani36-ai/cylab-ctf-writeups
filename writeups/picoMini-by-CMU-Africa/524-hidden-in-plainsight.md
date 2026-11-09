# Writeup: Hidden in plainsight (Challenge ID: 524)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / JPEG COM Marker Carving & Steghide DCT Steganography
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** Yahaya Meddy
- **Event:** picoMini by CMU-Africa
- **Flag (Resmi CyLab):** `academy{h1dd3n_1n_1m4g3_d0c4a4e2}`
- **Flag Platform Asli:** `picoCTF{h1dd3n_1n_1m4g3_d0c4a4e2}`
- **Flag Komunitas:** `CTF{h1dd3n_1n_1m4g3_d0c4a4e2}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), ITU-T Recommendation T.81 / ISO/IEC 10918-1 (JPEG Compression Syntax), RFC 4648 §4 (The Base 64 Alphabet), CWE-312 (Cleartext Storage of Sensitive Information), & CWE-532 (Insertion of Sensitive Information into Log / Metadata File).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Digital Forensics & Steganography Analysis*, peserta diuji dalam mengidentifikasi metadata berkas multimedia tersembunyi serta mengekstraksi data terenkripsi:
- **Skenario Tantangan:** Diberikan sebuah berkas gambar JPEG biasa (`img.jpg`). Peserta diminta menganalisis struktur biner gambar, mendeteksi saluran tersembunyi (*covert payload*), dan mengekstrak flag rahasia yang tersimpan di dalamnya.
- **Deskripsi Soal:** *"You’re given a seemingly ordinary JPG image. Something is tucked away out of sight inside the file. Your task is to discover the hidden payload and extract the flag. Download the jpg image img.jpg."*
- **Petunjuk Resmi:**
  1. *"Download the jpg image and read its metadata."*
- **Batasan Lingkungan & Scope Audit:**
  1. Ekstraksi dan analisis struktur segmen penanda biner (*marker segment*) format JPEG standar ISO/IEC 10918-1 / ITU-T T.81.
  2. Isolasi penanda komentar (*Comment Marker* `COM` / `0xFFFE`) dan pemecahan pengkodean Base64 berulang RFC 4648.
  3. Pemanfaatan kata sandi yang ditemukan untuk memulihkan payload terenkripsi menggunakan algoritma steganografi koefisien DCT (*Discrete Cosine Transform*) via `steghide`.
  4. Verifikasi integritas token secara otomatis melalui endpoint REST API CyLab Academy (`POST /api/submissions/`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Penanda Biner Format JPEG (ITU-T T.81 / ISO/IEC 10918-1):**
   Berkas JPEG/JFIF tersusun atas serangkaian blok penanda (*marker*) yang diawali dengan byte awalan `0xFF` diikuti satu byte penanda tipe:
   - `0xFFD8`: *Start of Image* (SOI).
   - `0xFFE0`: *JFIF Application Marker* (APP0).
   - `0xFFFE`: *Comment Marker* (COM), digunakan untuk menyimpan komentar teks atau metadata bebas hingga 65.535 byte.
   - `0xFFD9`: *End of Image* (EOI).
   Pada berkas `img.jpg`, penyerang/pengembang menyisipkan segmen komentar `COM` (`0xFFFE`) yang menyimpan string Base64:
   ```text
   c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9
   ```

2. **Kerapuhan Penyimpanan Kredensial Statis pada Metadata (CWE-312 / CWE-532):**
   Pengembang bermaksud mengamankan payload menggunakan enkripsi steganografi, namun kunci sandi ekstraksi (*passphrase*) justru ditinggalkan secara terbuka di dalam segmen komentar gambar dalam bentuk pengkodean Base64 yang tidak memberikan perlindungan kriptografis nyata:
   - Dekode Base64 Lapisan 1:
     $$\mathtt{base64\_decode}(\text{"c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9"}) \longrightarrow \text{"steghide:cEF6endvcmQ="}$$
     Awalan `steghide:` memberikan indikasi langsung mengenai utilitas steganografi yang digunakan.
   - Dekode Base64 Lapisan 2:
     $$\mathtt{base64\_decode}(\text{"cEF6endvcmQ="}) \longrightarrow \text{"pAzzword"}$$
     Menghasilkan kata sandi ekstraksi `pAzzword`.

3. **Mekanisme Steganografi DCT Steghide (Graph-Theoretic Steganography):**
   `steghide` menyembunyikan data ke dalam koefisien Discrete Cosine Transform (DCT) pada berkas gambar JPEG. Berbeda dengan teknik Least Significant Bit (LSB) sederhana pada ruang spasial, `steghide` mengoperasikan pencocokan graf bobot minimum (*minimum weight matching*) untuk meminimalkan perubahan frekuensi koefisien sehingga tidak menimbulkan degradasi visual atau perubahan mencolok pada histogram warna. Namun, karena kata sandi ekstraksi tersimpan di metadata, seluruh payload dapat dipulihkan secara deterministik.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pemeriksaan Metadata dan Penanda Biner:**
   Gunakan utilitas `file` atau `exiftool` untuk memeriksa metadata `img.jpg`:
   ```bash
   file img.jpg
   # Output: img.jpg: JPEG image data, JFIF standard 1.01, ..., comment: "c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9"
   ```
   Atau periksa posisi penanda biner secara manual menggunakan Python / `xxd`:
   ```bash
   xxd img.jpg | grep -A 2 "fffe"
   ```

2. **Dekode Bertingkat Pasfrase Steghide:**
   Lakukan dekode Base64 secara sekuensial:
   ```bash
   echo "c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9" | base64 -d
   # steghide:cEF6endvcmQ=
   echo "cEF6endvcmQ=" | base64 -d
   # pAzzword
   ```
   Dikonfirmasi pasfrase ekstraksi adalah `pAzzword`.

3. **Ekstraksi Data Rahasia Menggunakan Steghide:**
   Jalankan perintah ekstraksi steghide dengan kata sandi yang telah diperoleh:
   ```bash
   steghide extract -sf img.jpg -p pAzzword -xf flag.txt
   ```
   Hasil ekstraksi mengonfirmasi penemuan berkas teks:
   ```bash
   cat flag.txt
   # academy{h1dd3n_1n_1m4g3_d0c4a4e2}
   ```

4. **Eksekusi Solver Otomatis & Verifikasi API CyLab:**
   Jalankan skrip reproduksi mandiri `scripts/solve_524_hidden_in_plainsight.py`:
   ```bash
   python3 scripts/solve_524_hidden_in_plainsight.py
   ```
   Output eksekusi:
   ```text
   === [CyLab Academy] Solusi Modul #524: Hidden in plainsight ===
   [*] Mengunduh artefak tantangan dari https://challenge-files.cylabacademy.net/library/.../img.jpg...
   [*] JPEG COM Marker berhasil diekstrak: 'c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9'
   [*] Steghide Passphrase berhasil didekode: 'pAzzword'
   [+] Flag berhasil direkonstruksi: academy{h1dd3n_1n_1m4g3_d0c4a4e2}
   [+] Integritas token terverifikasi 100%: academy{h1dd3n_1n_1m4g3_d0c4a4e2}
   ```
   Pengiriman token ke `POST /api/submissions/` menghasilkan respons HTTP 201 Created dengan status valid (`correct: true`).

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{h1dd3n_1n_1m4g3_d0c4a4e2}`
- **Flag Native picoCTF:** `picoCTF{h1dd3n_1n_1m4g3_d0c4a4e2}`
- **Flag Komunitas:** `CTF{h1dd3n_1n_1m4g3_d0c4a4e2}`
- **Verifikasi REST API:** `POST https://learn.cylabacademy.org/api/submissions/` -> HTTP 201 Created (`{"user": 1072359, "challenge": 524, "correct": true, "historical": false}`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Pada uji kompetensi LKS Cyber Security Nasional bidang *Digital Forensics & Data Exfiltration Prevention*:
1. **Pembersihan Metadata File Media (Metadata Stripping):**
   Setiap berkas media yang diunggah pengguna ke portal web, CMS, atau media sosial wajib melalui pipeline sanitasi (*data cleaning*) untuk menghapus seluruh segmen EXIF, IPTC, XMP, dan penanda komentar (`COM`). Gunakan pustaka seperti `ImageMagick` (`mogrify -strip`) atau `libvips` untuk membersihkan metadata berbahaya.
2. **Rekonstruksi & Rekompresi Citra (Transcoding Pipeline):**
   Untuk menghancurkan payload steganografi berbasis DCT atau bit-plane LSB, sistem penyimpanan harus mendekompresi gambar ke bentuk raster bitmap mentah dan mengompresinya kembali (*re-encoding / re-quantization*) dengan parameter tabel kuantisasi baru. Proses ini merusak koefisien tersembunyi tanpa mengurangi kualitas visual gambar secara signifikan.
3. **Pendeteksian Saluran Komunikasi Terselubung (Covert Channel Detection):**
   Pada arsitektur pertahanan *Network Data Loss Prevention* (DLP), lalu lintas unggahan berkas gambar wajib dipindai terhadap anomali rasio entropi dan keberadaan teks terenkode Base64 pada header berkas biner guna mencegah eksfiltrasi data sensitif perusahaan.
