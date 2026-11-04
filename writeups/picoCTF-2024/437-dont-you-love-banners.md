# 437 - dont-you-love-banners (General Skills, picoCTF 2024, Medium)

## Challenge Metadata
- ID: 437 | Event: picoCTF 2024
- Category: General Skills | Difficulty: Medium (2)
- Author: CyLab Academy / picoCTF
- Points: 300 Pts
- Flag: `academy{b4nn3r_gr4bb1n9_su((3sfu11y_d3ce8df1}`

## Problem Statement & Scope
Tantangan mengoperasikan dua port layanan jaringan pada host container yang sama:
1. Port pertama membocorkan informasi sensitif melalui banner SSH default (`chatelaine.cylabacademy.net 25468`).
2. Port kedua menjalankan aplikasi daemon interaktif (`chatelaine.cylabacademy.net 31728`) yang meminta kata sandi dan serangkaian pertanyaan kuis keamanan siber, lalu memberikan shell bash terbatas sebagai pengguna `player`.
Deskripsi menyatakan: *"Can you abuse the banner? The server has been leaking some crucial information... From the above information abuse the machine and find the flag in the /root directory."* dengan petunjuk symlink dan password guessing.
Objektif pengujian (NIST SP 800-115 / MITRE ATT&CK T1059.004 & T1068): Menganalisis kebocoran banner jaringan, memvalidasi otentikasi shell interaktif, mengidentifikasi miskonfigurasi penanganan berkas banner MOTD berhak akses root, merekonstruksi eksploitasi symlink arbitrary file read, dan membaca berkas `/root/flag.txt`.

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Cleartext Credential Leakage via Service Banner (CWE-200 / CWE-522):**
   Layanan jaringan sekunder pada port 25468 dikonfigurasi untuk menampilkan string versi OpenSSH yang dimodifikasi sehingga memuat kata sandi statis secara terbuka:
   `SSH-2.0-OpenSSH_9.6p1 My_Passw@rd_@1234`.
2. **Insecure File Handling in Elevated Process (Symlink Following):**
   Daemon utama yang mendengarkan pada port 31728 dieksekusi dengan hak istimewa `root`. Saat koneksi baru masuk, skrip pembungkus membaca berkas `/home/player/banner` dan mencetak isinya ke socket jaringan sebelum menampilkan prompt password:
   ```python
   with open('/home/player/banner', 'r') as f:
       print(f.read())
   ```
3. **Privilege Boundary Failure via Insecure Direct Object Reference:**
   Meskipun berkas `/root/flag.txt` hanya memiliki izin baca untuk pengguna `root` (`-r-------- 1 root root`), berkas `/home/player/banner` berada di direktori milik pengguna `player` (`/home/player/`) dan dapat dihapus atau diganti.
   Dengan menghapus berkas teks asli dan membuat *symbolic link* (soft link) yang mengarah ke `/root/flag.txt`:
   ```bash
   rm -f /home/player/banner && ln -s /root/flag.txt /home/player/banner
   ```
   proses root yang membaca banner pada koneksi berikutnya akan mengikuti symlink tersebut (*symlink traversal*) dan membaca isi berkas rahasia `/root/flag.txt` atas nama pengguna root, lalu memancarkannya ke klien eksternal.

## Rekonstruksi Eksploitasi Step-by-Step
1. Tahap 1 — Banner Grabbing & Credential Recovery:
   - Melakukan koneksi socket TCP ke endpoint leaking port: `nc chatelaine.cylabacademy.net 25468`.
   - Menerima respons banner: `SSH-2.0-OpenSSH_9.6p1 My_Passw@rd_@1234`.
   - Mengekstrak kata sandi: `My_Passw@rd_@1234`.
2. Tahap 2 — Otentikasi dan Interaksi Kuis Shell:
   - Menghubungkan socket ke port aplikasi: `nc chatelaine.cylabacademy.net 31728`.
   - Mengirim kata sandi yang dipulihkan: `My_Passw@rd_@1234`.
   - Menjawab pertanyaan trivia keamanan:
     - *"What is the top cyber security conference in the world?"* -> `DEFCON`
     - *"the first hacker ever was known for phreaking(making free phone calls), who was it?"* -> `John Draper`
   - Server memberikan akses shell interaktif: `player@challenge:~$ `.
3. Tahap 3 — Symlink Weaponization:
   - Memeriksa struktur direktori kerja:
     `ls -la /home/player` memuat berkas `banner` dan direktori `/root` memuat `flag.txt` (terkunci `Permission denied` bagi user `player`).
   - Mengganti berkas banner dengan tautan simbolik ke flag root:
     `rm -f /home/player/banner && ln -s /root/flag.txt /home/player/banner`
   - Memutuskan koneksi shell.
4. Tahap 4 — Eksfiltrasi Flag via Koneksi Ulang:
   - Membuka sesi TCP baru ke `chatelaine.cylabacademy.net 31728`.
   - Proses root membaca `/home/player/banner`, mengikuti tautan ke `/root/flag.txt`, dan mengirimkan isinya sebagai pesan selamat datang pembuka:
     `academy{b4nn3r_gr4bb1n9_su((3sfu11y_d3ce8df1}`.
5. Verifikasi REST API CyLab:
   - Mengirim token flag ke REST API `POST /api/submissions/` dengan payload `{"challenge": 437, "flag": "academy{b4nn3r_gr4bb1n9_su((3sfu11y_d3ce8df1}"}`.
   - Respons platform: `HTTP 201 Created` dengan `correct: true`.
6. Terminasi instance:
   - Mengirim permintaan `DELETE /api/challenges/437/instance/` untuk membersihkan container lab.

## Flag & Verifikasi
- Flag Resmi: `academy{b4nn3r_gr4bb1n9_su((3sfu11y_d3ce8df1}`
- Bukti Validasi: REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created (`correct: true`, user 1072359).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Principle of Least Privilege (PoLP):** Layanan daemon jaringan tidak boleh dijalankan dengan identitas akun `root`. Jalankan layanan di bawah pengguna khusus tidak berhak istimewa (*dedicated unprivileged system service account*).
- **Safe File Open Operations & Symlink Protection:** Hindari membuka berkas di direktori yang dapat ditulisi pengguna (`writable by untrusted users`) dari proses berhak akses tinggi. Gunakan flag `O_NOFOLLOW` pada pemanggilan sistem `open()` untuk menolak pembacaan tautan simbolik, atau periksa kepemilikan berkas menggunakan `fstat()`.
- **Linux Kernel Hardening (`fs.protected_symlinks`):** Aktifkan parameter kernel sysctl:
  `fs.protected_symlinks = 1`
  yang mencegah symlink diikuti jika berada di direktori sticky yang dapat ditulisi publik dan kepemilikan tautan tidak sesuai dengan pemilik berkas target.
