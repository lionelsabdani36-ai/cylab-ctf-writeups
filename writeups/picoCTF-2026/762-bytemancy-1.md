# Writeup: bytemancy 1 (Challenge ID: 762)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Byte Encoding & Socket Automation (NIST SP 800-115 §4.2)
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{h0w_m4ny_e's???_6fd2faa9}`
- **Flag Komunitas:** `CTF{h0w_m4ny_e's???_6fd2faa9}`

---

## Problem Statement & Scope

Tantangan menguji kompetensi otomasi skrip jaringan dan pemahaman representasi data biner level rendah:
> *"Can you conjure the right bytes? The program's source code can be downloaded here."*
> *Petunjuk: "No copy-pasta, please - use Python!"*

Layanan tantangan mengekspos soket TCP interaktif pada kontainer on-demand yang menjalankan skrip Python `app.py`. Program mencetak banner grafis ASCII dan meminta masukan pengguna dengan pesan:
```text
Send me ASCII DECIMAL 101 1751 times, side-by-side, no space.
```
Setelah menerima input melalui panggilan fungsi standar `input('==> ')`, program memeriksa kecocokan string secara mutlak terhadap konstanta `"\x65" * 1751`. Jika cocok, berkas `./flag.txt` dibaca dan dikirimkan kembali kepada klien.

---

## Teori & Akar Kerentanan (Root Cause Theory)

Analisis statis kode sumber `app.py` mengungkap karakteristik kerentanan logika dan batas validasi:

1. **RFC 20 / Pemetaan Karakter ASCII Desimal ke Heksadesimal:**
   - Standar RFC 20 (US-ASCII) mendefinisikan tabel karakter 7-bit. Nilai desimal 101 merepresentasikan karakter huruf kecil `'e'`:
     $$\text{dec}(101) = \text{hex}(0x65) = \text{ASCII}('e')$$
   - Ekspresi Python `"\x65" * 1751` mengevaluasi string yang terdiri atas 1.751 karakter huruf `'e'` berturut-turut tanpa spasi.

2. **CWE-20 & CWE-307 / Kontrol Akses Berbasis Teka-Teki Statis Tanpa Proof-of-Work:**
   - Server mengandalkan panjang input ekstrem (1.751 byte) sebagai penghalang manual (*anti-copy-paste defense*).
   - Di lingkungan terminal interaktif, mencoba menyalin atau mengetik 1.751 karakter secara manual akan terpotong oleh batas buffer PTY/TTY terminal (biasanya 1024 atau 4096 byte kanonik) atau menghasilkan latensi yang memicu socket timeout.
   - Karena server tidak menerapkan rate limiting, tantangan cryptographic nonce, atau mitigasi brute-force, transmisi terprogram via pustaka soket POSIX (`socket.sendall`) menembus validasi tersebut dalam hitungan milidetik.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Kode Sumber `app.py`:**
   - Mengunduh dan meneliti file `app.py` dari repositori CDN CyLab:
     ```python
     user_input = input('==> ')
     if user_input == "\x65"*1751:
         print(open("./flag.txt", "r").read())
         break
     ```
   - Logika verifikasi murni mensyaratkan 1.751 byte berturut-turut dengan nilai ASCII 0x65 (huruf `e`).

2. **Penyusunan Payload Terprogram:**
   - Membangun payload dalam format string biner:
     ```python
     payload = ("e" * 1751) + "\n"
     ```
   - Panjang payload tepat 1.752 byte (termasuk delimiter newline `\n` untuk memicu terminasi `input()` pada Python server).

3. **Transmisi Socket TCP:**
   - Membuka koneksi socket TCP ke host dan port instans target (`chatelaine.cylabacademy.net:41819`):
     ```python
     import socket
     s = socket.create_connection((HOST, PORT), timeout=15)
     banner = s.recv(4096)
     s.sendall(payload.encode("ascii"))
     response = s.recv(4096).decode("utf-8")
     ```
   - Server memvalidasi string input dan mengembalikan isi berkas `flag.txt`.
   - Skrip reproduktif terverifikasi: `scripts/solve_762_bytemancy_1.py`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{h0w_m4ny_e's???_6fd2faa9}`
- **Format Flag Komunitas:** `CTF{h0w_m4ny_e's???_6fd2faa9}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 762, "flag": "academy{h0w_m4ny_e's???_6fd2faa9}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Otomasi Pemrosesan Stream Soket (Socket Stream Automation):**
   - Dalam kompetensi LKS Cyber Security bidang *Speed Scripting* dan *General Skills*, peserta dilatih untuk tidak pernah bergantung pada antarmuka terminal interaktif ketika menangani data biner bervolume tinggi.
   - Pemanfaatan modul native `socket` Python dengan penanganan buffer `sendall()` dan parsing regex non-blocking menjadi standar baku otomasi eksploitasi protokol kustom.

2. **Mitigasi Sisi Server (CWE-20 & CWE-307 Hardening):**
   - Jangan pernah menggunakan teka-teki statis atau panjang string sebagai mekanisme perlindungan autentikasi.
   - Terapkan mekanisme Proof-of-Work (PoW berbasis Hashcash/SHA-256) untuk mencegah otomasi tanpa izin pada layanan komputasi intensif.
   - Terapkan batas panjang buffer masukan maksimum (*maximum payload length ceiling*) secara tegas pada lapisan middleware sebelum memproses string di lapisan logika aplikasi.
