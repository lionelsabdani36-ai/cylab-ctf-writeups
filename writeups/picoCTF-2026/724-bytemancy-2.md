# Writeup: bytemancy 2 (Challenge ID: 724)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Raw Byte Socket I/O & Encoding Disambiguation
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** picoCTF
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{3ff5_4_d4yz_31bc4875}`
- **Flag Komunitas:** `CTF{3ff5_4_d4yz_31bc4875}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), CWE-172 (Encoding Error), CWE-20 (Improper Input Validation), & RFC 20 (7-Bit American Standard Code for Information Interchange).

---

## Problem Statement & Scope

Pada modul bimbingan teknis `bytemancy 2`, peserta diuji dalam pemahaman fundamental representasi data biner pada antarmuka jaringan tingkat rendah (*raw socket stream*):
- Skenario lingkungan: Layanan daemon Python interaktif berjalan pada kontainer on-demand yang diakses melalui koneksi TCP netcat (`nc chatelaine.cylabacademy.net <port>`).
- Pernyataan tantangan:
  > *"Can you conjure the right bytes? The program's source code can be downloaded here. Send me the HEX BYTE 0xFF 3 times, side-by-side, no space."*
- Petunjuk resmi:
  1. *"There's no way to print these bytes"*
  2. *"Use pwntools to send raw bytes over the network"*
- Sasaran evaluasi: Mengidentifikasi perbedaan kritis antara representasi teks terminal ber-encoding UTF-8/ASCII dengan stream biner mentah (*raw bytes*), menyusun transmisi paket socket TCP tanpa melalui translasi karakter terminal emulator, mengekstrak token rahasia, serta memvalidasinya pada endpoint REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Mekanisme Buffer Input Biner vs String Teks (POSIX Byte Stream):**
   Pada kode sumber layanan (`app.py`), pembacaan masukan pengguna tidak menggunakan fungsi `input()` berbasis string tingkat tinggi, melainkan mengakses penyangga biner standar secara langsung:
   ```python
   user_input = sys.stdin.buffer.readline().rstrip(b"\n")
   if user_input == b"\xff\xff\xff":
       print(open("./flag.txt", "r").read())
   ```
   Metode `sys.stdin.buffer.readline()` membaca deretan byte mentah (tipe data `bytes` pada Python 3) hingga menemukan pembatas baris (`0x0A` / `\n`). Pengecekan dilakukan secara deterministik terhadap nilai heksadesimal persis `b"\xff\xff\xff"` (3 byte bernilai numerik 255 berturut-turut).

2. **Divergensi Encoding Karakter & Jebakan Terminal (CWE-172):**
   Tantangan ini mengeksploitasi kesalahpahaman umum mengenai translasi encoding:
   - **Jebakan Literal ASCII:** Jika praktisi mengetikkan string `\xff\xff\xff` pada terminal bash/netcat biasa, emulator mengirimkan 12 karakter ASCII terpisah: `0x5c 0x78 0x66 0x66 0x5c 0x78 0x66 0x66 0x5c 0x78 0x66 0x66`. Penyangga server menerima 12 byte dan menolak masukan.
   - **Jebakan UTF-8 Codepoint:** Karakter `ÿ` pada tabel ISO-8859-1 (Latin-1) menempati nilai ordinal `0xFF`. Namun, pada sistem operasi modern yang menggunakan lokalitas UTF-8, karakter `ÿ` dikodekan menjadi representasi multi-byte variabel: `0xC3 0xBF`. Jika dikirimkan tiga kali, penyangga menerima deretan 6 byte `\xc3\xbf\xc3\xbf\xc3\xbf`, bukan 3 byte `0xFF`.
   - **Invalid UTF-8 Standalone Byte:** Nilai byte tunggal `0xFF` dalam spesifikasi RFC 3629 (UTF-8) didefinisikan sebagai byte yang dilarang (*illegal byte*) karena tidak pernah menjadi bagian dari urutan prefiks atau kelanjutan valid UTF-8 mana pun. Akibatnya, byte ini tidak dapat disalin atau dicetak secara konvensional melalui clipboard antarmuka grafis.

3. **Implikasi Arsitektural dalam Protokol Jaringan:**
   Dalam pengujian penetrasi dan audit biner, protokol jaringan seringkali mencampur header berbasis teks (seperti HTTP, SMTP) dengan muatan biner (*binary payloads*, seperti TLS records, RPC serialization, atau network packet framing). Kegagalan membedakan stream byte mentah dengan representasi string menyebabkan korupsi muatan eksploit (*payload mutilation*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Statis Kode Sumber `app.py`:**
   Melakukan inspeksi terhadap berkas sumber yang disediakan:
   ```bash
   curl -s "https://challenge-files.cylabacademy.net/library/7562c570e5785aa1277d9532b9a320206a86ca0646a5d89ef6e9ba239384b55e/app.py"
   ```
   Dikonfirmasi bahwa kondisi keberhasilan mensyaratkan `user_input == b"\xff\xff\xff"`.

2. **Penyusunan Script Interaksi Socket TCP Bersih:**
   Membuat modul otomasi socket mandiri yang mengabaikan layer string formatting dan langsung menulis buffer byte ke stream TCP:
   ```python
   import socket

   payload = b"\xff\xff\xff\n"
   with socket.create_connection((host, port), timeout=15) as s:
       banner = s.recv(4096)
       s.sendall(payload)
       response = s.recv(4096).decode('utf-8', errors='replace')
   ```

3. **Verifikasi Simulasi Unit Test Lokal:**
   Menguji logika penanganan byte pada lingkungan terisolasi untuk membuktikan kegagalan masukan berbasis ASCII maupun UTF-8 dan memastikan keberhasilan muatan raw bytes.

4. **Eksekusi Eksploitasi & Ekstraksi Token:**
   Saat muatan `b"\xff\xff\xff\n"` diterima, daemon membuka berkas `./flag.txt` dan memancarkan token resmi ke stdout.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{3ff5_4_d4yz_31bc4875}`
- **Flag Komunitas:** `CTF{3ff5_4_d4yz_31bc4875}`
- **Log Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 724,
    "flag": "academy{3ff5_4_d4yz_31bc4875}",
    "correct": true,
    "historical": false
  }
  ```
  Status respons HTTP: `201 Created` mengonfirmasi token valid dan tercatat secara definitif.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Rekomendasi Remediasi & Hardening (Defensive Perspective):**
   - **Validasi Skema Input Ketat (CWE-20):** Jika layanan mengharapkan input dalam representasi biner, gunakan pembungkus serialisasi standar (seperti Base64, Hexadecimal, atau Protobuf) yang aman terhadap transmisi jaringan berbasis teks:
     ```python
     user_hex = input("Send 3 hex bytes (e.g. FFFFFF): ").strip()
     if bytes.fromhex(user_hex) == b"\xff\xff\xff":
         ...
     ```
   - **Penerapan Batas Panjang & Timeout:** Pastikan buffer biner dibatasi panjang maksimumnya (`readline(limit=64)`) guna mencegah eksploitasi serangan penolakan layanan (Denial of Service) akibat masukan tak berhingga.

2. **Relevansi Modul LKS Cyber Security:**
   - **Network & Protocol Analysis:** Pemahaman mendalam mengenai transmisi raw TCP socket adalah prasyarat mutlak dalam modul *Network Security Assessment* dan *Custom Protocol Fuzzing*.
   - **Binary Exploitation Foundation:** Eksploitasi binary (*ret2win*, buffer overflow, shellcoding) membutuhkan injeksi alamat memori dalam urutan byte mentah (*little-endian raw bytes*). Peserta tidak boleh bergantung pada input teks terminal biasa saat menyusun payload eksploitasi.
