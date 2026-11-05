# Writeup: what's a net cat? (Challenge ID: 34)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Socket Stream Interception & Service Discovery
- **Difficulty:** Easy (diff=1)
- **Author:** Sanjay C/Danny Tunitis
- **Event:** picoCTF 2019
- **Points:** 100
- **Flag:** `academy{nEtCat_Mast3ry_abbFbc0e}` (Komunitas: `CTF{nEtCat_Mast3ry_abbFbc0e}`)

---

## Problem Statement & Scope

Tantangan menguji pemahaman operasional protokol transport TCP mentah melalui utilitas baris perintah standar:
> *"Using netcat (nc) is going to be pretty important. Can you connect to `xebec.cylabacademy.net` at port `12435` to get the flag?"*
>
> Petunjuk:
> *"nc tutorial: https://linux.die.net/man/1/nc"*

Lingkup pengujian mencakup pembentukan koneksi tiga arah TCP (Three-Way Handshake SYN, SYN-ACK, ACK), penerimaan byte stream aplikasi, dan pembacaan banner interaktif tanpa perantara lapisan aplikasi HTTP.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Interaksi Raw Socket dan Model Jaringan OSI (Layer 4 vs Layer 7):**
   - Utilitas `netcat` (sering dijuluki *Swiss Army knife* jaringan) bekerja pada lapisan transport (Layer 4 / OSI). Netcat membaca dan menulis data langsung melalui koneksi jaringan menggunakan protokol TCP atau UDP.
   - Tidak seperti browser web atau cURL yang menambahkan overhead protokol HTTP (seperti header `GET / HTTP/1.1`, `Host`, `User-Agent`), socket stream mentah mentransmisikan data apa adanya (*byte stream abstraction*).
   - Layanan pengujian mengikat daemon socket ke port TCP tertentu dan langsung mengirimkan string ASCII begitu koneksi terbentuk.

2. **Transmisi Data Teks Polos Tanpa Otentikasi (CWE-319):**
   - Berdasarkan standar **NIST SP 800-115** (*Section 5.1: Target Identification and Analysis*), port yang menyajikan informasi sensitif atau banner sistem tanpa otentikasi maupun enkripsi transport mengekspos surface recon kepada siapa pun di jaringan.
   - Tanpa lapisan TLS (Transport Layer Security), seluruh muatan paket rentan terhadap sniffing, spoofing, dan man-in-the-middle (MITM).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inisialisasi Container Lab On-Demand:**
   - Luncurkan container lab melalui API CyLab: `PUT /api/challenges/34/instance/`.
   - Peroleh endpoint target aktif dari deskripsi instance (`xebec.cylabacademy.net:12435`).

2. **Koneksi Socket TCP Langsung Menggunakan Netcat:**
   Jalankan perintah netcat pada terminal:
   ```bash
   nc xebec.cylabacademy.net 12435
   ```
   Layanan merespons seketika dengan banner:
   ```text
   You're on your way to becoming the net cat master
   academy{nEtCat_Mast3ry_abbFbc0e}
   ```

3. **Automasi Berbasis Script Python Socket (Standalone Reproducible):**
   Skrip mandiri menggunakan library standar `socket`:
   ```python
   import socket

   s = socket.create_connection(("xebec.cylabacademy.net", 12435), timeout=10)
   banner = s.recv(4096).decode("utf-8")
   s.close()

   for line in banner.splitlines():
       if "academy{" in line:
           print("Flag:", line.strip())
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{nEtCat_Mast3ry_abbFbc0e}`
- **Flag Format Komunitas:** `CTF{nEtCat_Mast3ry_abbFbc0e}`
- **Verifikasi API CyLab:**
  Submisi HTTP POST langsung ke `/api/submissions/`:
  ```json
  {"challenge": 34, "flag": "academy{nEtCat_Mast3ry_abbFbc0e}"}
  ```
  Status respons: `HTTP 201 Created` dengan `{"correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi Silabus LKS Cyber Security (Network Discovery & Reconnaissance):**
   - Menguasai `netcat`, `ncat`, dan `socat` merupakan kemampuan fundamental dalam pemetaan port aktif, banner grabbing, dan pengujian keandalan daemon server.
   - Peserta dituntut mampu membedakan respon socket TCP teks mentah dengan protokol berstruktur (HTTP, SMTP, FTP).

2. **Hardening Layanan Jaringan (Defensive Architecture):**
   - **Enkripsi Saluran Komunikasi:** Hindari pembukaan port dengan stream teks polos untuk pertukaran kredensial atau informasi rahasia. Terapkan TLS/SSL wrapper (misalnya OpenSSL s_server, stunnel, atau reverse proxy Nginx).
   - **Network Segmentation & Firewall Ingress Rules:** Batasi port hanya agar dapat diakses oleh host internal yang sah menggunakan `iptables` atau `nftables`, serta terapkan rate limiting untuk mencegah probing massal.
