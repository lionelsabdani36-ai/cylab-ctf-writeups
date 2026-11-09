# Writeup: Flag in Flame (Challenge ID: 523)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Log Data Obfuscation & Hex Visual Reconstruction
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** Prince Niyonshuti N.
- **Event:** picoMini by CMU-Africa
- **Flag (Resmi CyLab):** `academy{forensics_analysis_is_amazing_2043dbd1}`
- **Flag Platform Asli:** `picoCTF{forensics_analysis_is_amazing_2043dbd1}`
- **Flag Komunitas:** `CTF{forensics_analysis_is_amazing_2043dbd1}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 4648 §4 (The Base 64 Alphabet), ISO/IEC 15948:2004 / W3C PNG Specification (Magic Bytes), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), & CWE-532 (Insertion of Sensitive Information into Log File).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Digital Forensics & Security Operations Center (SOC) Incident Response*, peserta diuji dalam mengidentifikasi anomali berkas log serta membongkar skema penyelundupan data rahasia (*data steganography/obfuscation*):
- **Skenario Tantangan:** Tim SOC mendeteksi berkas log berukuran tidak wajar (`logs.txt`) pasca-insiden keamanan (data breach). Saat berkas dibuka, operator tidak menemukan baris syslog biasa, melainkan satu blok masif teks terenkode.
- **Deskripsi Soal:** *"The SOC team discovered a suspiciously large log file after a recent breach. When they opened it, they found an enormous block of encoded text instead of typical logs. Could there be something hidden within? Your mission is to inspect the resulting file and reveal the real purpose of it. Download the encoded data here: logs.txt."*
- **Petunjuk Resmi:**
  1. *"Use base64 to decode the data and generate the image file."*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis karakter dan pola pembuka (*header preamble*) aliran data Base64 RFC 4648.
  2. Rekonstruksi biner menjadi format citra digital Portable Network Graphics (PNG) ISO/IEC 15948.
  3. Pemeriksaan visual kanvas citra resolusi tinggi untuk mengekstrak deretan heksadesimal tersembunyi.
  4. Dekode hexadecimal ke representasi string ASCII dan verifikasi token ke API CyLab.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Penyelundupan Data dan Obfuskasi Log (MITRE ATT&CK T1001.001 / CWE-532):**
   Pada insiden keamanan nyata, aktor ancaman (*threat actor*) sering kali menyamarkan artefak biner curian (tangkapan layar dokumen rahasia, dump kredensial) dengan cara mengonversinya ke representasi ASCII teks menggunakan Base64, lalu menyimpannya di direktori log sistem (misal `/var/log/`) agar luput dari pemindaian berbasis tanda tangan biner sederhana.

2. **Identifikasi Tanda Tangan Awal Melalui Base64 (Magic Bytes in Base64):**
   Spesifikasi berkas PNG mendefinisikan 8-byte signature wajib:
   $$\mathtt{\backslash x89PNG\backslash r\backslash n\backslash x1a\backslash n} = \mathtt{0x89\ 0x50\ 0x4E\ 0x47\ 0x0D\ 0x0A\ 0x1A\ 0x0A}$$
   Ketika 3 byte pertama `0x89 0x50 0x4E` dikonversi ke Base64:
   $$\mathtt{0x89504E}_{16} = \mathtt{10001001\ 01010000\ 01001110}_2$$
   Dipetakan per 6-bit:
   - $100010_2 = 34 \rightarrow \text{'i'}$
   - $010101_2 = 21 \rightarrow \text{'V'}$
   - $000001_2 = 1 \rightarrow \text{'B'}$
   - $001110_2 = 14 \rightarrow \text{'O'}$
   Menghasilkan 4 karakter awal `iVBO`. Keberadaan awalan `iVBORw0KGgo` pada berkas teks Base64 merupakan indikator pasti bahwa payload biner di dalamnya adalah berkas gambar PNG tanpa perlu melakukan dekode menyeluruh terlebih dahulu.

3. **Rekonstruksi Heksadesimal Kanvas Grafis:**
   Setelah didekode, citra menampilkan ilustrasi antarmuka hacker. Pada margin paling bawah kanvas citra tertera deretan karakter heksadesimal mentah sepanjang 96 karakter:
   ```text
   61636164656D797B666F72656E736963735F616E616C797369735F69735F616D617A696E675F32303433646264317D
   ```
   Setiap pasangan 2 karakter heksadesimal merepresentasikan tepat 1 byte kode karakter ASCII. Misalnya `0x61 = 'a'`, `0x63 = 'c'`, `0x61 = 'a'`, `0x64 = 'd'`, `0x65 = 'e'`, `0x6D = 'm'`, `0x79 = 'y'`, `0x7B = '{'`, yang secara langsung membentuk token bendera resmi.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Header Berkas Log:**
   Periksa beberapa baris awal berkas `logs.txt`:
   ```bash
   head -c 30 logs.txt
   # Output: iVBORw0KGgoAAAANSUhEUgAAA4AAAA
   ```
   Dikonfirmasi bahwa karakter pembuka adalah `iVBO`, menandakan data biner terenkapsulasi adalah berkas citra PNG.

2. **Dekode Aliran Data Base64 ke Format PNG:**
   Ekstrak seluruh aliran data teks ke dalam berkas biner:
   ```bash
   base64 -d logs.txt > reconstructed.png
   file reconstructed.png
   # Output: reconstructed.png: PNG image data, 896 x 1152, 8-bit/color RGBA, non-interlaced
   ```

3. **Ekstraksi String Heksadesimal:**
   Buka citra `reconstructed.png` atau lakukan cropping pada margin bawah gambar. Terbaca deretan teks heksadesimal:
   ```text
   61636164656D797B666F72656E736963735F616E616C797369735F69735F616D617A696E675F32303433646264317D
   ```

4. **Inversi Heksadesimal ke Plaintext ASCII:**
   Konversi string heksadesimal menggunakan Python:
   ```python
   hex_val = "61636164656D797B666F72656E736963735F616E616C797369735F69735F616D617A696E675F32303433646264317D"
   flag = bytes.fromhex(hex_val).decode('utf-8')
   print(flag)
   # academy{forensics_analysis_is_amazing_2043dbd1}
   ```

5. **Eksekusi Solver Mandiri & Verifikasi REST API:**
   Jalankan skrip `scripts/solve_523_flag_in_flame.py`:
   ```bash
   python3 scripts/solve_523_flag_in_flame.py
   ```
   Output eksekusi:
   ```text
   === [CyLab Academy] Solusi Modul #523: Flag in Flame ===
   [*] Mengunduh berkas log artefak dari https://challenge-files.cylabacademy.net/library/.../logs.txt...
   [*] Berhasil memvalidasi PNG signature (1194153 bytes).
   [+] Flag berhasil direkonstruksi: academy{forensics_analysis_is_amazing_2043dbd1}
   [+] Integritas token terverifikasi 100%: academy{forensics_analysis_is_amazing_2043dbd1}
   ```
   Kirimkan payload JSON `{"challenge": 523, "flag": "academy{forensics_analysis_is_amazing_2043dbd1}"}` ke endpoint `POST /api/submissions/`. Server mengonfirmasi respon HTTP 201 Created dengan atribut `{"correct": true}`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{forensics_analysis_is_amazing_2043dbd1}`
- **Flag Native picoCTF:** `picoCTF{forensics_analysis_is_amazing_2043dbd1}`
- **Flag Komunitas:** `CTF{forensics_analysis_is_amazing_2043dbd1}`
- **Verifikasi REST API:** `POST https://learn.cylabacademy.org/api/submissions/` -> HTTP 201 Created (`{"user": 1072359, "challenge": 523, "correct": true, "historical": false}`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Pada uji kompetensi LKS Cyber Security Nasional bidang *SOC Operations & Log Integrity Monitoring*:
1. **Analisis Anomali Entropi dan Ukuran Berkas Log:**
   Berkas log teks normal memiliki variasi panjang baris dan rentang entropi Shannon berkisar 3.5 hingga 5.0. Satu blok data tanpa newline dengan entropi tinggi ($\approx 6.0$) menandakan keberadaan payload terenkode/terkompresi yang diselundupkan penyerang.
2. **Penerapan File Integrity Monitoring (FIM):**
   Aktifkan FIM (seperti OSSEC, Wazuh, atau auditd) pada seluruh direktori log `/var/log/`. Setiap pembuatan berkas log baru yang tidak berasosiasi dengan daemon resmi sistem harus memicu alert prioritas tinggi (Severity Critical).
3. **Penyimpanan Log Terpusat (Centralized WORM Logging):**
   Menerapkan arsitektur *Write-Once, Read-Many* (WORM) dengan mengalirkan log secara real-time melalui Syslog-ng / Logstash ke SIEM eksternal. Penyerang lokal tidak dapat memodifikasi atau menyelundupkan data ke berkas log tanpa tercatat di repositori audit eksternal.
