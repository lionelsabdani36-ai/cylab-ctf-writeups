# Writeup: Eavesdrop (Challenge ID: 264)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / PCAP Network Protocol Analysis
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{nc_73115_411_02612719}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan analisis forensik lalu lintas jaringan paket data (PCAP) dan dekripsi kriptografi:
> *"Download this packet capture and find the flag."*
> Tautan Artefak: `capture.flag.pcap` (ukuran ~7.5 KB)

Peserta diberikan rekaman tangkapan paket jaringan `capture.flag.pcap`. Skenario mensimulasikan transmisi data antara dua host pada jaringan lokal di mana komunikasi sensitif dan berkas terenkripsi dikirimkan melalui saluran transmisi tanpa proteksi lapisan transport (cleartext TCP transport).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Protokol TCP (RFC 793) & Ketiadaan TLS:**
   - Protokol Transmission Control Protocol (TCP) pada model OSI Layer 4 bertugas menjamin keandalan pengiriman paket data stream (handshake 3 arah SYN-SYN/ACK-ACK, pengurutan nomor sekuensial, dan reassembly segmen).
   - Namun, TCP murni tidak menyediakan enkripsi, autentikasi endpoint, maupun integritas kriptografis pada lapisan transport. Tanpa perlindungan enkripsi transport seperti TLS 1.3 (RFC 8446), seluruh data aplikasi (Layer 7) dapat disadap secara pasif (*passive packet sniffing*) oleh penyerang di jalur perutean jaringan (CWE-319: Cleartext Transmission of Sensitive Information).

2. **Penyaluran Kredensial dan Kunci pada Saluran Kontrol Terbuka (CWE-319 & OAT-008):**
   - Dalam sesi tangkapan, dua aliran TCP paralel terbentuk:
     - **Port 9001 (Saluran Kontrol / Chat):** Dua entitas berkomunikasi via aplikasi obrolan teks tanpa enkripsi. Salah satu pihak secara eksplisit menanyakan cara dekripsi berkas dan pihak lawan membocorkan sintaks perintah OpenSSL lengkap beserta kata sandi simetrisnya:
       `openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123`
     - **Port 9002 (Saluran Data Transfer):** Segera setelah negosiasi pada port 9001 selesai, pengirim mentransfer berkas biner mentah melalui port 9002.
   - Kebocoran kunci bersama (*pre-shared key*) pada saluran komunikasi yang sama dengan transfer data menggugurkan kerahasiaan seluruh lapisan kriptografi.

3. **Kelemahan Algoritma Enkripsi Warisan Triple-DES (CWE-327):**
   - Berkas data dienkripsi menggunakan Triple-DES (DES3 / 3DES / TDEA). 3DES merupakan algoritma warisan dengan ukuran blok 64-bit yang rentan terhadap serangan tabrakan ulang tahun (*Sweet32 attack*, CVE-2016-2183) dan telah didepresiasi oleh NIST SP 800-131A Rev. 2.
   - Header berkas terenkripsi memuat penanda format OpenSSL klasik `Salted__` (8 bita pertama: `\x53\x61\x6c\x74\x65\x64\x5f\x5f`) diikuti 8 bita garam acak (*salt*), yang memvalidasi format berkas OpenSSL EVP.

4. **Kepatuhan Metodologi NIST SP 800-115 (§ 5.2):**
   - Sesuai standar NIST SP 800-115 Section 5.2 (Network Traffic Analysis & Forensics), investigator membedah struktur bingkai Ethernet II (14 bita MAC), memeriksa penanda IPv4 (IHL dan protokol 6 = TCP), mengidentifikasi pasangan port komunikasi aktif, menyusun ulang (*reassemble*) muatan segmen TCP sesuai urutan sequence number, dan merekonstruksi artefak digital utuh.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak PCAP:**
   Unduh berkas tangkapan jaringan dari repositori resmi CyLab Academy:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/c977944192b56a1ea682a56c80d1b9622b72b63a3750b24b7a597d9726edbc9d/capture.flag.pcap
   ```

2. **Triase Forensik Lalu Lintas Jaringan:**
   Periksa ringkasan paket atau jalankan `tshark` / `wireshark` / parsing Python untuk meninjau stream TCP:
   ```bash
   tshark -r capture.flag.pcap -Y "tcp" -T fields -e tcp.stream -e ip.src -e ip.dst -e tcp.port | sort -u
   ```
   Ditemukan dua percakapan TCP utama pada port tujuan 9001 dan 9002.

3. **Inspeksi Stream Obrolan Port 9001:**
   Ekstraksi teks pada stream port 9001:
   ```text
   Hey, how do you decrypt this file again?
   You're serious?
   Yeah, I'm serious
   *sigh* openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
   Ok, great, thanks.
   Let's use Discord next time, it's more secure.
   C'mon, no one knows we use this program like this!
   Whatever.
   Hey.
   Yeah?
   Could you transfer the file to me again?
   Oh great. Ok, over 9002?
   Yeah, listening.
   Sent it
   Got it.
   You're unbelievable
   ```
   Ditemukan kata sandi: `supersecretpassword123` dan algoritma `des3`.

4. **Ekstraksi Muatan Biner Stream Port 9002:**
   Ambil muatan segmen TCP pada port 9002 dan simpan ke dalam berkas `file.des3`:
   ```bash
   tshark -r capture.flag.pcap -Y "tcp.port == 9002 && tcp.payload" -T fields -e tcp.payload | tr -d '\n' | xxd -r -p > file.des3
   ```
   Periksa header berkas:
   ```bash
   xxd file.des3 | head -n 1
   ```
   Keluaran:
   ```text
   00000000: 5361 6c74 6564 5f5f c6a5 b07e 8a4c 3259  Salted__...~.L2Y
   ```
   Konfirmasi keberadaan penanda `Salted__` valid.

5. **Dekripsi Kriptografi OpenSSL:**
   Jalankan perintah dekripsi dengan kata sandi yang bocor:
   ```bash
   openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
   cat file.txt
   ```
   Keluaran:
   ```text
   academy{nc_73115_411_02612719}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{nc_73115_411_02612719}`
- **Verifikasi API Platform:** Penyerahan token melalui REST API CyLab (`POST /api/submissions/`) tervalidasi dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 264, "flag": "academy{nc_73115_411_02612719}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Peserta LKS Cyber Security bidang Network Forensics dituntut mampu membedah format mentah paket PCAP (Header Global 24 bita, Header Paket 16 bita, Ethernet Frame, IPv4 Packet, TCP Segment), melakukan TCP stream reassembly secara mandiri tanpa bergantung pada GUI Wireshark, dan mengorelasikan artefak intelijen jaringan (*multi-stream correlation*).
- **Mitigasi Defensif (Transport Layer Hardening & Cryptographic Hygiene):**
  1. *Wajib Enkripsi Saluran Transport (TLS 1.3):* Seluruh komunikasi data dan obrolan internal jaringan wajib dilapisi protokol transport aman berbasis TLS 1.3 dengan cipher suite modern (misalnya AES-256-GCM atau ChaCha20-Poly1305) dan menonaktifkan protokol teks terbuka.
  2. *Pemisahan Saluran Manajemen Kunci (Out-of-Band Key Exchange):* Kunci enkripsi dan kata sandi tidak boleh dikirimkan melalui saluran data yang sama tanpa enkripsi asimetris (*public-key cryptography*) atau mekanisme pertukaran kunci Diffie-Hellman / ECDH dengan Perfect Forward Secrecy (PFS).
  3. *Depresiasi Algoritma Kriptografi Usang:* Tinggalkan penggunaan DES, 3DES, dan cipher blok 64-bit sesuai anjuran NIST SP 800-131A, gantikan dengan cipher berbasis AEAD modern.
  4. *KDF Modern:* Hindari penggunaan derivasi kunci sederhana berbasis opsi `-k` string langsung; gunakan algoritma PBKDF2, Argon2, atau scrypt dengan iterasi tinggi untuk memperlambat serangan brute-force.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_264_eavesdrop.py`.
