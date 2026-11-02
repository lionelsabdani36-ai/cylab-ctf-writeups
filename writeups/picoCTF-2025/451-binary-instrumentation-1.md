# Writeup: Binary Instrumentation 1 (Challenge ID: 451)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Windows Binary Instrumentation & LZMA Unpacking
- **Difficulty:** Medium
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2025
- **Points:** 100
- **Flag:** `academy{w4ke_m3_up_w1th_fr1da_f27acc38}`

---

## Problem Statement & Scope
Tantangan menyajikan sebuah berkas eksekusi biner Windows PE32+ (x86-64) berjudul `bininst1.exe` yang dikompresi dalam arsip berpasword ZIP (`academy`). Deskripsi tantangan mengisyaratkan penggunaan fungsi sinkronisasi Windows API untuk menidurkan thread program (*sleep condition variable*), dan menantang peserta untuk "membangunkan" program menggunakan Dynamic Binary Instrumentation (DBI) seperti Frida (`frida-trace`) guna mendapatkan flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyelubungan Kode Melalui Seksi Khusus (`.ATOM` / LZMA Compression):**
   Pemeriksaan struktur header PE32+ mengungkapkan seksi kustom bernama `.ATOM` yang dimulai pada offset fisik berkas `0x6000` dengan ukuran virtual `0x6ae4a` byte:
   - Header seksi ini diawali dengan runtutan byte penanda format LZMA (`0x5D 0x00 0x00 0x10 0x00`), yang mendefinisikan parameter kamus kompresi LZMA sebesar 1 MB (`0x00100000`).
   - Rutinitas *stub loader* pada seksi `.text` bertugas mengekstrak muatan terkompresi ini ke memori saat runtime sebelum menyerahkan eksekusi.
   - Dekompresi stream LZMA secara statis langsung mengekstraksi berkas biner PE32+ internal (*inner executable*) berukuran 2.333.029 byte tanpa memerlukan eksekusi dinamis pada OS Windows.

2. **Mekanisme Sinkronisasi Thread Windows API:**
   Pada berkas biner internal yang telah didekompresi, program memanfaatkan primitif konkurensi Windows:
   - `InitializeConditionVariable`
   - `SleepConditionVariableCS`
   - `WakeAllConditionVariable` / `WakeConditionVariable`
   Program menginisialisasi critical section dan menempatkan thread kerja pada status *blocked* menggunakan `SleepConditionVariableCS`, menunggu sinyal bangun dari thread lain atau peristiwa sistem.

3. **Intended Path (Dynamic Binary Instrumentation via Frida):**
   Secara desain kompetisi, peserta diharapkan meluncurkan aplikasi di bawah pengawasan Frida toolkit:
   ```bash
   frida-trace -i "Wake*" bininst1.exe
   ```
   Atau menyuntikkan script Frida JavaScript untuk memanggil `WakeAllConditionVariable` secara paksa, sehingga thread yang tertidur terbangun dan mencetak flag ke konsol.

4. **Vektor Analisis Statis Defensif:**
   Karena proteksi packer hanya berupa kompresi LZMA tanpa enkripsi asimetris ataupun hashing terdistribusi, string teks dan logika program pada biner internal dapat dianalisis secara statis. Di dalam seksi `.rdata` biner internal, ditemukan string keluaran lengkap:
   `Ok, I'm Up! The flag is: YWNhZGVteXt3NGtlX20zX3VwX3cxdGhfZnIxZGFfZjI3YWNjMzh9`
   yang merupakan representasi Base64 dari flag kompetisi.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Header PE dan Deteksi Seksi `.ATOM`:**
   ```bash
   objdump -h bininst1.exe
   ```
   Ditemukan seksi `.ATOM` pada offset `0x6000`.
2. **Pemeriksaan Magic Byte Kompresi:**
   Membaca 5 byte pertama pada offset `0x6000` mengonfirmasi header LZMA (`5d 00 00 10 00`).
3. **Dekompresi Muatan Biner Menggunakan Python `lzma`:**
   ```python
   import lzma
   with open("bininst1.exe", "rb") as f:
       raw = f.read()
   decompressed = lzma.decompress(raw[0x6000:])
   ```
4. **Pencarian Pola Base64 dan Dekode Flag:**
   ```python
   import base64, re
   m = re.search(rb"The flag is:\s*([A-Za-z0-9+/=]{20,})", decompressed)
   flag = base64.b64decode(m.group(1)).decode()
   print(flag)
   ```
   Hasil dekode:
   ```text
   academy{w4ke_m3_up_w1th_fr1da_f27acc38}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{w4ke_m3_up_w1th_fr1da_f27acc38}`
- **Verifikasi Platform:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 451, "flag": "academy{w4ke_m3_up_w1th_fr1da_f27acc38}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Relevansi Teknik Dynamic Instrumentation pada LKS:** Dynamic Binary Instrumentation (DBI) seperti Frida, Intel PIN, dan DynamoRIO merupakan keterampilan esensial pada kompetisi LKS Cyber Security bidang Reverse Engineering dan Malware Analysis. Analis dapat mengaitkan (*hook*) fungsi API sensitif, memodifikasi nilai balik register (*return value tampering*), dan melacak aliran data tanpa perlu melakukan dekompilasi menyeluruh atau modifikasi biner di disk.
- **Rekomendasi Remediasi Keamanan Perangkat Lunak:** Menyimpan rahasia sensitif (seperti token atau kunci enkripsi) dalam format plaintext atau Base64 sederhana di dalam biner yang dikemas hanya memberikan ilusi keamanan (*security through obscurity*). Pengembang wajib memanfaatkan enkripsi berbasis kunci derivasi dinamis (misalnya PBKDF2 atau HKDF) dengan kunci yang tidak tersimpan statis dalam file eksekusi, serta menerapkan teknik anti-tampering dan integritas memori.
