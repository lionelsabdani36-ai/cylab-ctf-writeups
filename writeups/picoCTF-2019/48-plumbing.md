# Writeup: plumbing (Challenge ID: 48)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Unix Stdout Pipelining & Stream Filtering
- **Difficulty:** Easy/Medium (diff=2)
- **Author:** Alex Fulton/Danny Tunitis
- **Event:** picoCTF 2019
- **Points:** 200
- **Flag:** `academy{digital_plumb3r_ef32328E}` (Komunitas: `CTF{digital_plumb3r_ef32328E}`)

---

## Problem Statement & Scope

Tantangan menguji manipulasi aliran I/O standar POSIX (Standard Streams: stdin, stdout) dan teknik penyaringan teks bervolume tinggi:
> *"Sometimes you need to handle process data outside of a file. Can you find a way to keep the output from this program and search for the flag? Connect to `chatelaine.cylabacademy.net 12198`."*
>
> Petunjuk:
> 1. *"Remember the flag format is academy{XXXX}"*
> 2. *"What's a pipe? No not that kind of pipe... This kind: http://www.linfo.org/pipes.html"*

Lingkup pengujian mencakup penanganan data stream berukuran besar (lebih dari 10.000 baris teks sampah/distractor) yang dialirkan secara berkelanjutan melalui koneksi socket TCP, serta pemanfaatan pipa Unix (*Unix pipeline*) untuk memfilter token sasaran secara instan tanpa membebani buffer terminal.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Konsep Pipa Unix (Unix Pipelines & POSIX Inter-Process Communication):**
   - Dalam filosofi Unix, pipa (`|`) adalah mekanisme IPC satu arah yang menghubungkan output standar (`stdout`, file descriptor 1) dari suatu proses langsung ke input standar (`stdin`, file descriptor 0) dari proses berikutnya.
   - Tanpa pipelining, aliran teks masif (ribuan baris per detik) akan membanjiri buffer terminal emulator (mengakibatkan *terminal lag* dan kesulitan observasi manual).
   - Dengan menghubungkan program jaringan (`netcat`) ke utilitas pemroses ekspresi reguler (`grep`), pemrosesan stream dilakukan secara *on-the-fly* di memori tanpa perlu menyimpan file sementara ke disk:
     $$\text{Socket TCP Stream} \xrightarrow{\text{stdout}} \text{nc} \xrightarrow{\text{pipe } |} \text{stdin} \rightarrow \text{grep "academy\{"} \xrightarrow{\text{stdout}} \text{Flag}$$

2. **Ketiadaan Pembatasan Laju Aliran Data (Unbounded Output Stream):**
   - Berdasarkan standar **NIST SP 800-115** (*Section 5.1: Network Discovery & Service Identification*), layanan yang menyemburkan ribuan entri data acak tanpa segmentasi atau mekanisme paging (*unbounded response payload*) berpotensi menimbulkan dampak Denial of Service (DoS) pada klien berdaya komputasi rendah.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inisialisasi Container Lab On-Demand:**
   - Luncurkan container lab melalui API CyLab: `PUT /api/challenges/48/instance/`.
   - Peroleh endpoint layanan aktif dari deskripsi instance (`chatelaine.cylabacademy.net:12198`).

2. **Pengamatan Aliran Data Tanpa Filter:**
   Menjalankan netcat langsung:
   ```bash
   nc chatelaine.cylabacademy.net 12198
   ```
   Layanan membanjiri terminal dengan lebih dari 10.000 baris teks pengalih seperti:
   ```text
   This is not the flag
   Keep looking...
   Not this one either
   I don't think this will help you find the flag
   ...
   ```

3. **Penyaringan Stream Melalui Unix Pipeline (`| grep`):**
   Gunakan pipa Unix untuk menyaring baris yang memiliki pola string `academy`:
   ```bash
   nc chatelaine.cylabacademy.net 12198 | grep -i --color=never "academy{"
   ```
   Sistem langsung mengisolasi baris target secara instan:
   ```text
   academy{digital_plumb3r_ef32328E}
   ```

4. **Automasi Berbasis Skrip Python (Buffered Stream Filtering):**
   Implementasi menggunakan buffer dan regex:
   ```python
   import socket, re

   s = socket.create_connection(("chatelaine.cylabacademy.net", 12198), timeout=10)
   buf = b""
   while True:
       chunk = s.recv(4096)
       if not chunk:
           break
       buf += chunk

   matches = re.findall(r"academy\{[^}]+\}", buf.decode("utf-8", errors="ignore"))
   print("Flag:", matches[0])
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{digital_plumb3r_ef32328E}`
- **Flag Format Komunitas:** `CTF{digital_plumb3r_ef32328E}`
- **Verifikasi API CyLab:**
  Submisi HTTP POST langsung ke `/api/submissions/`:
  ```json
  {"challenge": 48, "flag": "academy{digital_plumb3r_ef32328E}"}
  ```
  Status respons: `HTTP 201 Created` dengan `{"correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi Silabus LKS Cyber Security (Data Processing & Log Analysis):**
   - Kemampuan menyusun rantai pipa Unix (`|`, `grep`, `awk`, `sed`, `sort`, `uniq`, `cut`) adalah keahlian krusial bagi analis insiden (Incident Responder / SOC Analyst) di LKS untuk memfilter megabyte log akses web atau pcap mentah secara cepat di lingkungan headless.

2. **Hardening Layanan Jaringan (Defensive Architecture):**
   - **Pagination dan Rate Limiting:** Layanan jaringan yang mengembalikan banyak data wajib menerapkan paginasi (misal berbasis cursor/halaman) dan *rate limiting* untuk mencegah pemborosan bandwidth server dan kelelahan klien.
   - **Enkripsi Saluran Transport:** Gunakan TLS untuk memastikan aliran data tidak disadap atau dimanipulasi oleh pihak ketiga di jaringan perantara.
