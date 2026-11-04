# 432 - Blast from the past (Forensics, picoCTF 2024, Medium)

## Challenge Metadata
- ID: 432 | Event: picoCTF 2024
- Category: Forensics | Difficulty: Medium (2)
- Author: SYREAL
- Points: 200 Pts
- Flag: `academy{71m3_7r4v311ng_p1c7ur3_085c715f}`

## Problem Statement & Scope
Terdapat sebuah berkas citra digital (`original.jpg`) yang memerlukan manipulasi metadata forensik mendalam untuk memenuhi spesifikasi validasi waktu tertentu (*timestamp aging*). Penilai mengharuskan seluruh timestamp pada gambar disesuaikan secara presisi hingga tingkat milidetik menuju awal epoch Unix: `1970:01:01 00:00:00.001+00:00`.
Deskripsi menyatakan:
*"The judge for these pictures is a real fan of antiques. Can you age this photo to the specifications? Set the timestamps on this picture to `1970:01:01 00:00:00.001+00:00` with as much precision as possible for each timestamp. In this example, `+00:00` is a timezone adjustment... Submit your modified picture here: nc -w 2 chatelaine.cylabacademy.net <PORT> < original_modified.jpg. Check your modified picture here: nc chatelaine.cylabacademy.net <CHECK_PORT>."*

Objektif pengujian (NIST SP 800-115 / ISO/IEC 27037 Digital Evidence Forensics):
Melakukan inspeksi forensik pada segmen metadata EXIF, Composite sub-second tags, dan proprietary trailer metadata vendor, memodifikasi atribut tanggal dan milidetik secara presisi, mentransmisikan berkas hasil manipulasi ke server verifikasi, dan memulihkan token flag.

## Teori & Analisis Arsitektur Kerentanan
1. **Struktur Metadata Citra JPEG:**
   Berkas citra JPEG menyimpan metadata dalam berbagai penanda (*markers*) dan segmen struktur:
   - Header APP1 (`0xFFE1`): Menyimpan data standar TIFF/EXIF (IFD0, ExifIFD) seperti tanggal pembuatan kamera (`DateTimeOriginal`), tanggal digitalisasi (`CreateDate`), dan tanggal perubahan gambar (`ModifyDate`).
   - Tag Sub-detik (`SubSecTime`, `SubSecTimeOriginal`, `SubSecTimeDigitized`): Menyimpan fraksi detik (milidetik) yang digabungkan oleh pembaca forensik menjadi nilai komposit bertanda waktu tinggi.
   - Trailer Vendor Spesifik (Samsung Metadata Trailer): Banyak kamera ponsel cerdas (seperti Samsung Galaxy) menyematkan data tambahan di akhir berkas JPEG di luar segmen EXIF standar.
2. **Keterbatasan Alat Standar Forensik (ExifTool):**
   - Perintah `exiftool` mampu memodifikasi tag standar EXIF dan sub-detik secara mudah.
   - Namun, tag milik Samsung (`Samsung:TimeStamp`) disimpan sebagai string ASCII bertipe Unix millisecond epoch dalam trailer biner: `Image_UTC_Data1700513181420`.
   - Exiftool hanya dapat membaca tag ini (*read-only*), tetapi tidak dapat memperbarui atau menghapusnya secara otomatis.
3. **Rekayasa Biner Manual (Binary Patching):**
   - Timestamp asli `1700513181420` berkorespondensi dengan tanggal `2023:11:20 20:46:21.420 UTC`.
   - Untuk mencapai `1970:01:01 00:00:00.001 UTC`, nilai milidetik Unix epoch yang diinginkan adalah tepat 1 milidetik (`1`).
   - Karena format data pada trailer memerlukan panjang string 13 karakter numerik, nilai `1` dipadatkan dengan angka nol di depan menjadi: `0000000000001`.
   - Melakukan penggantian string biner `Image_UTC_Data1700513181420` menjadi `Image_UTC_Data0000000000001` mengubah nilai `Samsung:TimeStamp` menjadi `1970:01:01 00:00:00.001+00:00`.

## Rekonstruksi Eksploitasi Step-by-Step
1. Tahap 1 — Analisis Metadata Awal:
   - Mengunduh `original.jpg` dari direktori berkas CyLab.
   - Menjalankan analisis tag waktu:
     ```bash
     exiftool -s -time:all original.jpg
     ```
   - Teridentifikasi 7 tag waktu yang dipantau oleh server penguji.
2. Tahap 2 — Modifikasi Tag EXIF & SubSec via ExifTool:
   - Mengeksekusi penulisan nilai tanggal epoch pada berkas salinan `original_modified.jpg`:
     ```bash
     exiftool -overwrite_original \
       -AllDates="1970:01:01 00:00:00" \
       -SubSecTime=001 -SubSecTimeOriginal=001 -SubSecTimeDigitized=001 \
       -SubSecCreateDate="1970:01:01 00:00:00.001" \
       -SubSecDateTimeOriginal="1970:01:01 00:00:00.001" \
       -SubSecModifyDate="1970:01:01 00:00:00.001" \
       original_modified.jpg
     ```
3. Tahap 3 — Patching Binary Samsung Trailer:
   - Mencari pola biner `Image_UTC_Data1700513181420` pada offset biner berkas.
   - Mengganti nilai tersebut dengan `Image_UTC_Data0000000000001`.
   - Memverifikasi hasil modifikasi: `exiftool -Samsung:TimeStamp original_modified.jpg` menampilkan `1970:01:01 00:00:00.001+00:00`.
4. Tahap 4 — Transmisi Jaringan & Flag Extraction:
   - Mengaktifkan kontainer lab `PUT /api/challenges/432/instance/` untuk mendapatkan port submit (`38288`) dan check (`34430`).
   - Mengirim byte biner citra termodifikasi ke port submit `chatelaine.cylabacademy.net:38288`.
   - Menghubungkan socket ke port pemeriksa `chatelaine.cylabacademy.net:34430`.
   - Seluruh 7 pemeriksaan tag bernilai valid (`Great job, you got that one!`), dan server mengeluarkan token flag:
     `academy{71m3_7r4v311ng_p1c7ur3_085c715f}`.
5. Tahap 5 — Validasi Platform:
   - Mengirim token flag ke REST API CyLab: `POST /api/submissions/` dengan payload:
     `{"challenge": 432, "flag": "academy{71m3_7r4v311ng_p1c7ur3_085c715f}"}`.
   - Respons platform: `HTTP 201 Created` (`correct: true`, user 1072359).
   - Mengirim permintaan `DELETE /api/challenges/432/instance/` untuk membersihkan kontainer lab.

## Flag & Bukti Verifikasi
- Flag Resmi: `academy{71m3_7r4v311ng_p1c7ur3_085c715f}`
- Bukti Validasi: REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created (`correct: true`, user 1072359).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Forensik Metadata Multi-Layer:** Pemeriksaan integritas digital pada berkas multimedia harus memperhitungkan data EXIF standar, segmen XMP, serta ekstensi proprietary vendor (*vendor trailers*). Modifikasi parsial hanya pada header EXIF akan terdeteksi jika pemeriksa memvalidasi trailer data mentah.
- **Data Sanitization & Privacy Protection:** Sistem aplikasi yang menerima unggahan foto pengguna harus menerapkan sanitasi metadata (*metadata stripping*) untuk mencegah kebocoran informasi lokasi geospasial (GPS), identitas perangkat keras kamera, dan jejak waktu pengambilan gambar yang akurat.
- **Integritas Bukti Forensik:** Nilai hash kriptografis (SHA-256) harus selalu dihitung pada awal proses akuisisi bukti digital forensik guna mendeteksi segala bentuk perubahan timestamp atau anomali metadata pada berkas.