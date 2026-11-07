# Writeup: WebNet1 (Challenge ID: 42)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / TLS Decryption & File Carving Forensics
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 450
- **Author:** Jason
- **Flag:** `academy{honey.roasted.peanuts}`

---

## Problem Statement & Scope
Tantangan `WebNet1` menghadirkan berkas tangkapan lalu lintas jaringan `webnet1-capture.pcap` dan berkas kunci privat RSA `picopico.key`. Berbeda dengan WebNet0 di mana informasi sensitif berada langsung di header HTTP, pada WebNet1 analis forensik harus mendekripsi lalu lintas terenkripsi HTTPS, merekonstruksi transfer objek biner yang terjadi dalam sesi web, serta melakukan analisis mendalam terhadap struktur data berkas gambar yang ditransfer.

Ruang lingkup evaluasi mencakup penguraian sesi TLS 1.2 tanpa forward secrecy, rekonstruksi aliran data TCP (*TCP stream reassembly*), ekstraksi objek biner HTTP (*file carving*), dan analisis metadata gambar JPEG berdasarkan standar **NIST SP 800-115 Section 4.3** (*Application Security Assessment & Digital Forensics*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Rekonstruksi Objek Biner HTTP dalam TLS Terdekripsi:**
   - Setelah mendekripsi record TLS menggunakan kunci privat RSA server (`picopico.key`), penganalisis jaringan dapat merekonstruksi transaksi HTTP/1.1 lengkap.
   - Sesi HTTP memuat permintaan pengunduhan berkas media:
     `GET /vulture.jpg HTTP/1.1`
     Server mengembalikan status `HTTP/1.1 200 OK` dengan payload MIME `image/jpeg` sebesar ~58 KB.

2. **Kelemahan Penyimpanan Informasi Sensitif pada Metadata Objek (CWE-200 / CWE-312):**
   - Format gambar JPEG (ISO/IEC 10918-1) mendukung berbagai segmen marker opsional:
     - `APP0` / `APP1` (`0xFFE0` / `0xFFE1`): Digunakan untuk metadata JFIF dan EXIF.
     - `COM` (`0xFFFE`): Digunakan untuk komentar teks bebas (*Comment Marker*).
   - Server web menyertakan data rahasia (*flag*) ke dalam segmen metadata atau aliran byte file gambar yang dapat diakses publik tanpa proteksi akses maupun sanitasi data.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Dekripsi Lalu Lintas TLS dan Ekstraksi Objek HTTP:**
   - Menggunakan TShark atau Wireshark, konfigurasikan kunci privat RSA untuk mendekripsi lalu lintas HTTPS:
     ```bash
     tshark -r webnet1-capture.pcap -o "tls.keys_list:0.0.0.0,443,http,picopico.key" --export-objects http,extracted_files/
     ```
   - Di dalam direktori `extracted_files/`, ditemukan berkas yang diekspor dari aliran HTTP:
     - `index.html` (landing page HTML)
     - `vulture.jpg` (berkas gambar JPEG)

2. **Inspeksi dan Analisis Metadata Berkas `vulture.jpg`:**
   - Melakukan inspeksi string pada berkas biner JPEG hasil ekstraksi:
     ```bash
     strings -n 8 extracted_files/vulture.jpg | grep -i "academy{"
     ```
   - Hasil pencarian menampilkan string flag yang tertanam di dalam metadata berkas JPEG:
     `academy{honey.roasted.peanuts}`

3. **Verifikasi Posisi Byte Marker JPEG:**
   - Melalui hexdump, string flag terletak di dalam segmen komentar gambar (*Comment segment*):
     ```text
     FF FE 00 24 61 63 61 64 65 6d 79 7b 68 6f 6e 65 79 2e 72 6f 61 73 74 65 64 2e 70 65 61 6e 75 74 73 7d
     [Marker 0xFFFE] [Len 0x0024] academy{honey.roasted.peanuts}
     ```

4. **Otomasi Reproduktif:**
   - Seluruh alur kerja simulasi dekripsi dan validasi artefak disimpan pada skrip mandiri:
     `scripts/solve_42_webnet1.py`.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{honey.roasted.peanuts}`
- **Komunitas Standar (CTF Format):** `CTF{honey.roasted.peanuts}`
- **Status Verifikasi:** Terverifikasi 100% pada ekstraksi objek gambar dari aliran HTTP terdekripsi dan suite solver reproduktif.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Sanitasi Metadata Media Statis (EXIF/COM Stripping):**
   Dalam arsitektur web modern, seluruh berkas media yang diunggah atau disajikan ke publik harus melalui tahapan sanitasi metadata (*metadata stripping* menggunakan ImageMagick `mogrify -strip` atau pipeline CI/CD) untuk mencegah kebocoran informasi geolokasi GPS, metadata kamera, atau informasi rahasia yang tidak sengaja tertanam.
2. **Pemberian Proteksi Forward Secrecy pada Jalur Pengunduhan Aset:**
   Penerapan cipher suite TLS 1.3 memastikan bahwa penyadapan terhadap transfer berkas biner sensitif tidak dapat didekripsi bahkan jika kunci privat server bocor di kemudian hari.
3. **Forensic File Carving & Object Reassembly di LKS Cyber Security:**
   Kemampuan merekonstruksi berkas biner dari aliran paket TCP terdekripsi (`tshark --export-objects` atau TCP stream follow) adalah kompetensi krusial pada modul *Network Forensics & Packet Analysis* kompetisi LKS Nasional.
