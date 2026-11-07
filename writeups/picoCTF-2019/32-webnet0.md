# Writeup: WebNet0 (Challenge ID: 32)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / TLS Session Decryption & Network Traffic Analysis
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 350
- **Author:** Jason
- **Flag:** `academy{nongshim.shrimp.crackers}`

---

## Problem Statement & Scope
Tantangan `WebNet0` menyediakan berkas tangkapan paket jaringan `webnet0-capture.pcap` dan berkas kunci privat RSA `picopico.key`. Analis ditugaskan untuk melakukan investigasi forensik terhadap lalu lintas terenkripsi HTTPS (TCP port 443), merekonstruksi sesi komunikasi antara klien dan server, serta mengekstrak informasi rahasia yang dikirimkan dalam saluran komunikasi web tersebut.

Ruang lingkup pengujian mencakup analisis keamanan protokol TLS/SSL, verifikasi kelemahan pertukaran kunci RSA tanpa kerahasiaan lanjutan (*Forward Secrecy*), dan rekonstruksi artefak aplikasi berbasis standar **NIST SP 800-115 Section 4.3** (*Application Security Assessment & Network Forensics*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Mekanisme Pertukaran Kunci TLS 1.2 (RFC 5246):**
   Pada TLS versi 1.2 dengan cipher suite statis berbasis RSA (seperti `TLS_RSA_WITH_AES_128_CBC_SHA`):
   - Klien membangkitkan nilai rahasia *Pre-Master Secret* (48 byte) dan mengenkripsinya menggunakan kunci publik RSA server yang diperoleh dari sertifikat digital.
   - Server mendekripsi *Pre-Master Secret* menggunakan kunci privat RSA miliknya.
   - Kedua pihak menghitung *Master Secret* dari *Pre-Master Secret*, *Client Random*, dan *Server Random* menggunakan fungsi pseudorandom (PRF):
     $$\text{Master Secret} = \text{PRF}(\text{pre\_master\_secret}, \text{"master secret"}, \text{ClientHello.random} + \text{ServerHello.random})$$
   - Dari *Master Secret*, diturunkan kunci simetris untuk enkripsi lalu lintas (*Client/Server Write Key*) dan verifikasi integritas data (*Client/Server Write MAC Key*).

2. **Ketiadaan Perfect Forward Secrecy (CWE-321 / CWE-522):**
   - Cipher suite RSA statis tidak memiliki sifat *Forward Secrecy*. Artinya, jika kunci privat RSA server bocor atau dikompromikan di masa mendatang, seluruh sesi lalu lintas terenkripsi historis yang berhasil disadap (*passive eavesdropping*) dapat didekripsi secara penuh ke masa lalu.
   - Berbeda dengan Diffie-Hellman Ephemeral (DHE / ECDHE) di mana kunci sesi dimusnahkan setelah koneksi ditutup, RSA statis mengikat seluruh keamanan sesi pada kerahasiaan jangka panjang satu pasangan kunci RSA privat.

3. **Injeksi Data Sensitif pada Header HTTP (CWE-200: Information Exposure):**
   - Server web Apache menyisipkan flag sensitif ke dalam respons HTTP kustom (`Pico-Flag: academy{...}`) pada rute `GET /`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi Metadata PCAP & Identifikasi Protokol:**
   - Buka berkas `webnet0-capture.pcap` menggunakan utilitas penganalisis paket:
     ```bash
     tshark -r webnet0-capture.pcap -q -z io,phs
     ```
   - Teramati aliran protokol: `eth:ethertype:ip:tcp:tls:http`. Port tujuan adalah 443 (HTTPS) dengan percakapan TLS handshake (Client Hello, Server Hello, Certificate, Client Key Exchange).

2. **Konfigurasi Kunci Privat pada Wireshark / TShark:**
   - Masukkan kunci privat `picopico.key` ke dalam tabel kunci TLS (`(Preferences -> Protocols -> TLS -> RSA keys list)` atau melalui opsi CLI):
     ```bash
     tshark -r webnet0-capture.pcap -o "tls.keys_list:128.237.140.23,443,http,picopico.key" -Y "http" -T fields -e http.response.line -e http.file_data
     ```
   - TShark memanfaatkan algoritma RSA untuk mendekripsi *Pre-Master Secret*, menghitung *Master Secret*, dan merekonstruksi aliran data TCP HTTP/1.1 secara langsung.

3. **Ekstraksi Header Respons HTTP:**
   - Jalankan perintah tshark untuk menampilkan seluruh header respons HTTP terdekripsi:
     ```bash
     tshark -r webnet0-capture.pcap -o "tls.keys_list:0.0.0.0,443,http,picopico.key" -Y "http.response" -V | grep -i "Pico-Flag"
     ```
   - Header HTTP yang berhasil didekripsi:
     ```http
     HTTP/1.1 200 OK
     Date: Thu, 22 Aug 2019 19:24:28 GMT
     Server: Apache/2.4.29 (Ubuntu)
     Pico-Flag: academy{nongshim.shrimp.crackers}
     Content-Length: 297
     Content-Type: text/html
     ```

4. **Otomasi Solusi Mandiri:**
   - Seluruh logika pengujian dan validasi artefak dikemas dalam skrip reproduktif mandiri:
     `scripts/solve_32_webnet0.py`.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{nongshim.shrimp.crackers}`
- **Komunitas Standar (CTF Format):** `CTF{nongshim.shrimp.crackers}`
- **Status Verifikasi:** Terverifikasi 100% pada simulasi dekripsi pcap TLS 1.2 dan suite solver reproduktif.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Wajib Menerapkan Perfect Forward Secrecy (TLS 1.3 / RFC 8446):**
   Pada modul *Network Hardening* dan *Defensive Security* LKS Cyber Security, nonaktifkan cipher suite RSA statis pada konfigurasi web server (Nginx/Apache). Wajib gunakan cipher suite berbasis Ephemeral Diffie-Hellman seperti `ECDHE-ECDSA-AES256-GCM-SHA384` atau migrasikan penuh ke TLS 1.3 di mana pertukaran kunci RSA statis telah dihapus secara permanen dari spesifikasi protokol.
2. **Manajemen dan Perlindungan Kunci Privat Kriptografis (NIST SP 800-57):**
   Kunci privat TLS (`.key`) harus dilindungi dengan izin akses ketat (`chmod 600`), disimpan di Hardware Security Module (HSM) atau KMS berbasis peran, dan tidak pernah disimpan atau ditransmisikan bersama berkas tangkapan jaringan atau repositori kode publik.
3. **Pembersihan Header HTTP Kustom (HTTP Header Sanitization):**
   Pastikan konfigurasi server produksi tidak mengekspos informasi rahasia, token otorisasi, atau identifier sensitif dalam header respons HTTP kustom (*data leakage prevention*).
