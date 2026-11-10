# Writeup: chrono (Challenge ID: 347)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Linux Task Scheduling & System Crontab Reconnaissance (CWE-312 / CWE-200)
- **Difficulty:** Medium (diff=2)
- **Event:** picoCTF 2023
- **Points:** 100
- **Author:** LT 'syreal' Jones
- **Flag:** `academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}`

---

## Problem Statement & Scope

Tantangan menyajikan skenario investigasi administrasi sistem Linux interaktif:
> *"How to automate tasks to run at intervals on linux servers?*
> *Additional details will be available after launching your challenge instance.*
> *`ssh picoplayer@<host> -p <port>`"*

Peserta diberikan akses shell interaktif SSH ke lingkungan kontainer Linux Debian sebagai pengguna terbatas `picoplayer`. Saat login pertama kali, direktori kerja pengguna (`/home/picoplayer`) dalam keadaan kosong tanpa file atau artefak tersembunyi. Pertanyaan inti mengenai otomasi berkala pada sistem Linux secara langsung mengarahkan peserta pada mekanisme penjadwalan proses (*task scheduler*), khususnya subsistem Cron. Target analisis adalah melakukan enumerasi terstruktur terhadap konfigurasi penjadwalan berkala di tingkat pengguna dan sistem operasi untuk menemukan kredensial rahasia yang tertinggal.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Penjadwalan Tugas Linux (Vixie Cron Architecture):**
   Pada sistem operasi turunan UNIX dan distribusi Linux, otomasi proses berkala dikelola oleh daemon `cron` (atau `crond`). Terdapat pemisahan tegas antara dua tingkatan konfigurasi:
   - **Tingkat Pengguna (User Crontabs):** Dikelola via utilitas `crontab -e` / `crontab -l` dan disimpan di direktori terisolasi `/var/spool/cron/crontabs/<username>`.
   - **Tingkat Sistem (System-wide Crontab):** Dikonfigurasi langsung oleh administrator pada berkas `/etc/crontab` serta drop-in direktori `/etc/cron.d/`, `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, dan `/etc/cron.monthly/`.

2. **Format Standar Berkas `/etc/crontab`:**
   Berkas `/etc/crontab` memiliki struktur kolom:
   ```text
   # m h dom mon dow user  command
   ```
   Di mana kolom ke-6 memuat nama pengguna eksekutor (misalnya `root`) sebelum string perintah. Selain baris perintah aktif, berkas crontab sering kali memuat baris komentar yang diawali dengan tanda pagar (`#`).

3. **Kerentanan Penyimpanan Rahasia pada Berkas Berizin Longgar (CWE-312 & CWE-200):**
   - Secara bawaan (*default*), berkas `/etc/crontab` pada banyak instalasi Linux diberikan hak akses POSIX `644` (`-rw-r--r--`), yang berarti dapat dibaca oleh setiap pengguna lokal (*world-readable*).
   - Pengembang atau administrator sistem sering kali meninggalkan catatan konfigurasi internal, token pengujian, atau kredensial integrasi pada baris komentar crontab tanpa menyadari bahwa komentar tersebut tidak terisolasi dari proses non-root.
   - Ketiadaan kontrol kerahasiaan (*Lack of Confidentiality Controls*) memungkinkan pengguna non-root mengekstrak data sensitif tanpa memerlukan eskalasi privilese (*privilege escalation*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Konektivitas Sesi SSH Lab:**
   Lakukan koneksi remote SSH menggunakan kredensial yang diterbitkan pada deskripsi instance lab:
   ```bash
   ssh picoplayer@chatelaine.cylabacademy.net -p <port>
   ```

2. **Enumerasi Metodologis Sistem Operasi (NIST SP 800-115 §4.2):**
   - Periksa direktori home pengguna:
     ```bash
     pwd && ls -la
     ```
     Hasil menunjukkan direktori kosong tanpa petunjuk tersembunyi.
   - Periksa crontab pengguna aktif:
     ```bash
     crontab -l
     ```
     Menghasilkan respon `no crontab for picoplayer`.
   - Beralih ke evaluasi penjadwal sistem global:
     ```bash
     cat /etc/crontab
     ```

3. **Ekstraksi Token Sensitif:**
   Pembacaan berkas `/etc/crontab` langsung menampilkan konfigurasi sistem dengan komentar rahasia pada bagian header berkas:
   ```text
   # academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}
   SHELL=/bin/sh
   PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
   
   # Example of job definition:
   # .---------------- minute (0 - 59)
   # |  .------------- hour (0 - 23)
   # |  |  .---------- day of month (1 - 31)
   # |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
   # |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
   # |  |  |  |  |
   # *  *  *  *  * user-name command to be executed
   ```
   Token bendera berhasil diekstrak secara linier:
   `academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}`
- **Flag Komunitas:** `CTF{Sch3DUL7NG_T45K3_L1NUX_9bb09823}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 347, "flag": "academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}", "correct": true, "historical": false}
  ```
- **Status Solver:** Terverifikasi 100% pada eksekusi solver reproduktif di `scripts/solve_347_chrono.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Metodologi Post-Exploitation / Local Enumeration:**
   Dalam kompetensi LKS Cyber Security bidang Linux Administration & Defensive Analysis, kegagalan menemukan artefak di direktori pengguna mengharuskan peserta melakukan audit hierarki sistem standar: `/etc/`, `/var/log/`, `/opt/`, dan timer systemd (`systemctl list-timers`).
2. **Hardening Izin Berkas Penjadwalan Sistem:**
   Batasi izin baca berkas `/etc/crontab` dan direktori `/etc/cron.d/` agar hanya dapat diakses oleh superuser atau grup crontab:
   ```bash
   chmod 600 /etc/crontab
   chmod 700 /etc/cron.d
   ```
3. **Higienitas Komentar dan Manajemen Rahasia:**
   Jangan pernah mencatat kredensial, API key, atau token akses pada baris komentar skrip atau konfigurasi cron. Gunakan variabel lingkungan terisolasi atau vault manajer rahasia terenkripsi.
