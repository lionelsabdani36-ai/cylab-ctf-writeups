# Writeup: Trust But Verify (Challenge ID: 783)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / AI Ethics
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{7ru57_15_34rn3d_65d5434b}`

---

## Deskripsi Tantangan
> Play through an AI ethics interactive fiction where confident AI outputs can be wrong, subtly wrong, or almost-right. Verify claims, code, and citations to learn practical habits for safe AI-assisted work. Connect with netcat:
> `$ nc chatelaine.cylabacademy.net 31766`

---

## Analisis & Skenario Masalah
Tantangan ini menyajikan game fiksi interaktif berbasis socket TCP yang mensimulasikan interaksi antara pengguna (*Ren*) dan asisten AI (*ARIA*) dalam mengerjakan proposal sains.

Terdapat 3 skenario verifikasi kritis:
1. **The Statistic (Halusinasi Fakta & Sitasi Palsu):**
   - AI menghasilkan statistik dramatis: *"Over 500 million metric tons of plastic enter the world's oceans" (2022 UNEP report)*.
   - Pilihan: Meminta tautan sumber spesifik (`b`).
   - Hasil: AI mengakui mengalami halusinasi dan tidak dapat menemukan dokumen tersebut.
2. **The Code (Kesalahan Logika Tersembunyi / Silent Code Error):**
   - AI membuat script Python untuk menghitung rata-rata, tetapi menambahkan `+ 1` tanpa alasan yang jelas (`average = sum(data) / len(years) + 1`).
   - Kode berjalan tanpa error sintaks, tetapi menghasilkan output angka yang terdistorsi secara diam-diam.
   - Pelajaran: Membaca dan mengaudit kode sebelum dieksekusi.
3. **The Citation (Detail Nyata vs Subtly Wrong):**
   - AI memberikan studi nyata dari *Dr. Heather Leslie (Vrije Universiteit Amsterdam)* tentang mikroplastik dalam darah.
   - Pilihan: Memverifikasi secara independen (`b`).
   - Hasil: Peneliti dan studi tersebut nyata, namun tahun publikasinya keliru (2022, bukan 2021) dan status temuan masih awal (*preliminary*).

Di akhir skenario, asisten AI memberikan flag resmi sebagai reward atas kebiasaan verifikasi kritis.

---

## Solver Otomatis (Python)
Script otomasi dibuat menggunakan Python socket client untuk mem-parse prompt interaktif dan mengirimkan respons verifikasi:

```python
import socket
import time
import re

s = socket.socket()
s.settimeout(5)
s.connect(('chatelaine.cylabacademy.net', 31766))

def recv_until_prompt(sock):
    buf = ""
    while True:
        try:
            chunk = sock.recv(1024).decode('utf-8', errors='ignore')
            if not chunk:
                break
            buf += chunk
            if "[a/b/c]" in buf or "(Press Enter to continue...)" in buf or "academy{" in buf:
                break
        except socket.timeout:
            break
    return buf

while True:
    text = recv_until_prompt(s)
    if not text:
        break
    if "academy{" in text:
        print("[!] FLAG FOUND:", re.search(r"academy\{[^}]+\}", text).group(0))
        break
    if "(Press Enter to continue...)" in text:
        s.sendall(b"\n")
    elif "[a/b/c]" in text:
        s.sendall(b"b\n")  # Memilih opsi verifikasi sumber
    elif "[a/b]" in text:
        s.sendall(b"b\n")  # Memilih opsi audit independen
    else:
        s.sendall(b"\n")
    time.sleep(0.2)

s.close()
```

---

## Hasil Flag & Verifikasi
- **Flag yang Diperoleh:** `academy{7ru57_15_34rn3d_65d5434b}`
- **Status Submisi:** Berhasil disubmit ke endpoint `/api/submissions/` dan akun terverifikasi menyelesaikan tantangan (Total solved meningkat dari 59 menjadi 60).
