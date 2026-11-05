# Writeup: Nice netcat... (Challenge ID: 156)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Socket Stream Interception & ASCII Decimal Transformation
- **Difficulty:** Easy (diff=1)
- **Author:** syreal
- **Event:** picoCTF 2021
- **Points:** 15
- **Flag:** `academy{g00d_k1tty!_n1c3_k1tty!_6d1e6}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman interaksi socket TCP mentah dan representasi data biner/desimal karakter:
> *"There is a nice program that you can talk to by using this command in a shell: `$ nc <host> <port>`, but it doesn't speak English..."*
>
> Petunjuk:
> 1. Berlatih menggunakan netcat dengan modul what's a netcat.
> 2. Berlatih membaca dan menulis representasi karakter ASCII.

Lingkup pengujian mencakup penanganan transmisi data stream TCP, identifikasi pola encoding karakter, dan transformasi numerik desimal ke karakter teks ASCII.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Konsep Representasi Karakter ASCII (American Standard Code for Information Interchange):**
   - Karakter alfanumerik dalam arsitektur komputer dipetakan ke dalam bilangan bulat berukuran 7-bit atau 8-bit (rentang 0–127 pada standar ASCII dasar).
   - Misalnya, byte desimal `97` memetakan ke karakter huruf kecil `'a'`, `99` ke `'c'`, `100` ke `'d'`, `101` ke `'e'`, `109` ke `'m'`, `121` ke `'y'`, dan `123` ke simbol kurung kurawal pembuka `'{'`.
   - Ketika suatu layanan jaringan mentransmisikan nilai byte dalam representasi teks desimal per baris (`\n`), klien harus mem-parsing setiap nilai integer dan menerapkan fungsi konversi $f(n) = \text{chr}(n)$ untuk merekonstruksi aliran plaintext.

2. **Ketiadaan Enkripsi Transport & Integritas Payload (CWE-319):**
   - Berdasarkan standar NIST SP 800-115 (*Section 5.1: Network Discovery & Service Identification*), protokol berbasis socket TCP mentah (raw socket) tanpa TLS/mTLS tidak memberikan perlindungan kerahasiaan (*confidentiality*) maupun keaslian identitas (*authenticity*).
   - Data byte yang dikirimkan dapat dicegat, diinspeksi, atau diinjeksi ulang melalui MITM atau pemantauan paket lokal.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inisialisasi Container Lab On-Demand:**
   - Luncurkan container lab via `PUT /api/challenges/156/instance/`.
   - Ekstrak alamat host dan port aktif dari deskripsi instance (`xebec.cylabacademy.net:37271`).

2. **Intersepsi Aliran Socket TCP:**
   Koneksikan socket TCP ke endpoint dan tangkap aliran byte mentah:
   ```bash
   nc xebec.cylabacademy.net 37271
   ```
   Layanan merespons dengan aliran angka desimal baris demi baris:
   ```text
   97 
   99 
   97 
   100 
   101 
   109 
   121 
   123 
   103 
   48 
   48 
   100 
   ...
   ```

3. **Rekonstruksi Karakter Teks via Python:**
   Menggunakan one-liner atau skrip python untuk mentransformasikan setiap baris desimal:
   ```python
   import socket

   s = socket.create_connection(('xebec.cylabacademy.net', 37271), timeout=10)
   data = b''
   while True:
       chunk = s.recv(4096)
       if not chunk:
           break
       data += chunk
   s.close()

   lines = data.decode().splitlines()
   flag = ''.join(chr(int(x.strip())) for x in lines if x.strip().isdigit())
   print(flag)
   ```
   Hasil dekode menghasilkan flag resmi:
   `academy{g00d_k1tty!_n1c3_k1tty!_6d1e6}`

---

## Flag & Verifikasi

- **Flag:** `academy{g00d_k1tty!_n1c3_k1tty!_6d1e6}`
- **Verifikasi API CyLab:**
  Submisi HTTP POST langsung ke `/api/submissions/`:
  ```json
  {"challenge": 156, "flag": "academy{g00d_k1tty!_n1c3_k1tty!_6d1e6}"}
  ```
  Status respons: `HTTP 201 Created` dengan `{"correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Pemahaman Fundamental Layer Transport & Representasi Biner:**
   - Pada modul pengujian LKS Cyber Security, kemampuan membedah aliran TCP mentah dan memahami konversi representasi data (desimal, heksadesimal, oktal, base64) merupakan fondasi utama sebelum menangani protokol lapisan aplikasi yang lebih kompleks.

2. **Hardening Layanan Jaringan (Defensive Engineering):**
   - **Enkripsi Sesi (Transport Layer Security):** Hindari membuka daemon socket teks polos untuk transfer data sensitif. Gunakan TLS wrapper (misalnya via stunnel atau OpenSSL s_server) untuk memastikan kerahasiaan aliran data.
   - **Autentikasi & Kontrol Akses Jaringan:** Batasi paparan layanan hanya ke subnet terpercaya menggunakan firewall host (iptables/nftables) atau network access control list (NACL).
