# 384 - useless (General Skills, picoCTF 2023, Medium)

## Challenge Metadata
- ID: 384 | Event: picoCTF 2023 | Author: CyLab Academy
- Category: General Skills | Difficulty: Medium (2) | Points: 200
- Flag: `academy{us3l3ss_ch4ll3ng3_3xpl0it3d_4318}`

## Problem Statement & Scope
Tantangan memberikan akses remote terminal melalui protokol SSH (`picoplayer@chatelaine.cylabacademy.net:port`, password `password`). Di direktori home user (`/home/picoplayer`) terdapat script shell bernama `useless` yang menjalankan kalkulasi aritmetika sederhana. Peserta diarahkan untuk mengamati script dan menemukan flag kompetisi.

## Teori & Akar Kerentanan (Root Cause)
1. **Pola Enumerasi Sistem Linux Standar:**
   Ketika sebuah biner atau script sistem diletakkan pada sistem Linux, informasi panduan penggunaan umumnya didaftarkan pada subsistem manual (`man-db`).
2. **Indikasi pada Kode Sumber Shell:**
   Pemeriksaan isi script `cat useless` menunjukkan blok conditional parameter handling:
   ```bash
   if [ $# != 3 ]
   then
     echo "Read the code first"
   else
     ...
     else
       echo "Read the manual"
     fi
   fi
   ```
   Pesan `Read the manual` memberikan petunjuk langsung untuk memeriksa manual page dari program terkait.
3. **Penyimpanan Flag pada Bagian Man Page (Authors Section):**
   Saat perintah `man useless` dieksekusi, dokumen troff/groff manual page menampilkan ringkasan program, sintaks perintah, dan pada bagian `AUTHORS`:
   ```text
   Authors
          This script was designed and developed by Cylab Africa

          academy{us3l3ss_ch4ll3ng3_3xpl0it3d_4318}
   ```

## Rekonstruksi Eksploitasi Step-by-Step
1. **Akses SSH:**
   Melakukan koneksi SSH ke instans target:
   ```bash
   sshpass -p password ssh -p <port> picoplayer@chatelaine.cylabacademy.net
   ```
2. **Inspeksi Script Lokal:**
   Membaca kode bash `useless` untuk memverifikasi logika percabangan.
3. **Pemeriksaan Manual Page:**
   Menjalankan perintah `man useless` atau langsung membaca file troff di `/usr/share/man/man1/useless.1`.
4. **Ekstraksi Flag:**
   Menyaring string flag dari output manual.

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_384_useless.py`:
```python
import paramiko, re

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect("chatelaine.cylabacademy.net", port=39388, username="picoplayer", password="password")
stdin, stdout, stderr = client.exec_command("man useless")
out = stdout.read().decode()
flag = re.search(r"academy\{[^\}]+\}", out).group(0)
print("Flag:", flag)
```

## Mitigasi Defensif & Relevansi LKS Cyber Security
1. **Pembersihan Metadata & Dokumentasi Internal:**
   Dalam pengujian penetrasi dan audit kepatuhan, pengembang sering kali meninggalkan credential, token otorisasi, atau komentar sensitif di dalam file panduan pengguna (`man`, `--help`, docs internal) yang dapat diakses oleh user unprivileged.
2. **Relevansi Modul LKS:**
   Melatih keterampilan fundamental Linux system enumeration, navigasi dokumentasi subsistem man-db, dan pemahaman alur eksekusi script bash.
