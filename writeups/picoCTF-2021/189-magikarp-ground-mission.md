# Writeup: Magikarp Ground Mission (Challenge ID: 189)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Linux Filesystem Navigation & Privilege Boundary Reconnaissance
- **Difficulty:** Easy (diff=1)
- **Author:** syreal
- **Event:** picoCTF 2021
- **Points:** 30
- **Flag:** `academy{xxsh_0ut_0f_//4t3r_47c47679}` (Komunitas: `CTF{xxsh_0ut_0f_//4t3r_47c47679}`)

---

## Problem Statement & Scope

Tantangan menguji keterampilan navigasi hirarki direktori Unix/Linux, pemahaman perizinan berkas (file permissions), dan penelusuran artefak terdistribusi:
> *"Do you know how to move between directories and read files in the shell? Start the container, `ssh` to it, and then `ls` once connected to begin."*
>
> Kredensial SSH: `ctf-player` / `f6904eaa` pada host `chatelaine.cylabacademy.net:20530`.
>
> Petunjuk:
> *"Finding a cheatsheet for bash would be really helpful!"*

Lingkup investigasi mencakup penjelajahan lingkungan shell berbasis POSIX: direktori kerja awal (`~`), subdirektori (`~/drop-in`), root direktori sistem (`/`), serta penggabungan string token parsial menjadi satu kesatuan utuh.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Hirarki Berkas Standar Unix (FHS - Filesystem Hierarchy Standard):**
   - Sistem operasi berbasis Unix mengatur seluruh berkas dan perangkat di bawah satu pohon direktori tunggal berakar pada `/` (root directory).
   - Pengguna non-privilese (`ctf-player`) memiliki direktori beranda di `/home/ctf-player` (`~`). Namun, secara default pada konfigurasi izin POSIX standar (misal `chmod 755`), pengguna biasa tetap memiliki izin baca (`r`) dan eksekusi/traversal (`x`) pada sebagian besar direktori sistem, termasuk `/` dan `/etc`.
   - Menempatkan file rahasia dengan mode izin world-readable (`644` atau `-rw-r--r--`) di sembarang direktori sistem memungkinkan setiap pengguna lokal membaca isi file tersebut.

2. **Keterpaparan Berkas Sensitif Antar-Pengguna (CWE-552):**
   - Berdasarkan panduan **NIST SP 800-115** (*Section 5.1: System Auditing and Internal Host Discovery*), evaluasi konfigurasi sistem harus memverifikasi bahwa *least privilege* diterapkan secara ketat. Berkas yang berisi data privat tidak boleh diletakkan di direktori publik atau dibiarkan berstatus readable bagi grup `others`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inisialisasi Container Lab On-Demand:**
   - Luncurkan container lab melalui API CyLab: `PUT /api/challenges/189/instance/`.
   - Ekstrak kredensial SSH dari deskripsi instance (`ctf-player` / `f6904eaa` pada `chatelaine.cylabacademy.net:20530`).

2. **Otentikasi SSH dan Inspeksi Direktori Beranda:**
   Hubungkan sesi shell via SSH:
   ```bash
   ssh -p 20530 ctf-player@chatelaine.cylabacademy.net
   ```
   Daftar isi direktori:
   ```bash
   ctf-player@chatelaine:~$ ls -la
   -rw-r--r-- 1 root       root        9 Sep 23 02:31 3of3.flag.txt
   drwxr-xr-x 1 ctf-player ctf-player 59 Sep 23 02:31 drop-in
   ```
   Baca bagian ke-3 dari flag:
   ```bash
   ctf-player@chatelaine:~$ cat 3of3.flag.txt
   47c47679}
   ```
   Fragmen 3: `47c47679}`

3. **Inspeksi Subdirektori `drop-in`:**
   Masuk ke subdirektori:
   ```bash
   ctf-player@chatelaine:~$ cd drop-in && ls -la
   -rw-r--r-- 1 ctf-player ctf-player 14 Sep 23 00:59 1of3.flag.txt
   -rw-r--r-- 1 ctf-player ctf-player 56 Sep 23 00:59 instructions-to-2of3.txt
   ```
   Baca fragmen 1 dan petunjuk berikutnya:
   ```bash
   ctf-player@chatelaine:~/drop-in$ cat 1of3.flag.txt
   academy{xxsh_
   ctf-player@chatelaine:~/drop-in$ cat instructions-to-2of3.txt
   Next, go to the root of all things, more succinctly `/`
   ```
   Fragmen 1: `academy{xxsh_`

4. **Navigasi ke Root Filesystem (`/`):**
   Pindah ke direktori root:
   ```bash
   ctf-player@chatelaine:~/drop-in$ cd /
   ctf-player@chatelaine:/$ ls -la
   -rw-r--r-- 1 root root 15 Sep 23 00:59 2of3.flag.txt
   -rw-r--r-- 1 root root 51 Sep 23 00:59 instructions-to-3of3.txt
   ```
   Baca bagian ke-2 dari flag:
   ```bash
   ctf-player@chatelaine:/$ cat 2of3.flag.txt
   0ut_0f_//4t3r_
   ```
   Fragmen 2: `0ut_0f_//4t3r_`

5. **Rekonstruksi Token Flag Utuh:**
   Menggabungkan ketiga bagian:
   $$\text{Part 1} + \text{Part 2} + \text{Part 3} = \texttt{academy\{xxsh\_} + \texttt{0ut\_0f\_//4t3r\_} + \texttt{47c47679\}} = \texttt{academy\{xxsh\_0ut\_0f\_//4t3r\_47c47679\}}$$

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{xxsh_0ut_0f_//4t3r_47c47679}`
- **Flag Format Komunitas:** `CTF{xxsh_0ut_0f_//4t3r_47c47679}`
- **Verifikasi API CyLab:**
  Submisi HTTP POST langsung ke `/api/submissions/`:
  ```json
  {"challenge": 189, "flag": "academy{xxsh_0ut_0f_//4t3r_47c47679}"}
  ```
  Status respons: `HTTP 201 Created` dengan `{"correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi Silabus LKS Cyber Security (Linux Host Hardening & Navigation):**
   - Peserta wajib terbiasa menavigasi struktur direktori Unix (`cd`, `ls`, `pwd`), memahami *path relative* (`.`, `..`, `~`) vs *path absolute* (`/var`, `/etc`, `/tmp`), serta memanfaatkan *command line utilities* untuk investigasi artefak.

2. **Hardening Akses Berkas dan Partisi Sistem (Defensive Engineering):**
   - **Terapkan Izin Berkas Ketat (POSIX Permissions):** Berkas rahasia sistem wajib memiliki perizinan `chmod 600` atau `chmod 400` dengan pemilik `root:root`, sehingga pengguna non-privilese tidak dapat membacanya.
   - **Restrict World-Readable Root Directories:** Tempatkan direktori sensitif di luar jangkauan pembacaan publik dan audit secara berkala menggunakan auditd atau find:
     ```bash
     find / -type f -perm -004 -exec ls -l {} +
     ```
   - **Implementasi Linux Namespaces / Chroot Jail:** Jalankan layanan dengan batasan lingkungan chroot atau container yang membatasi pandangan proses terhadap filesystem induk.
