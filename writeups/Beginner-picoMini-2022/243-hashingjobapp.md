# Writeup: HashingJobApp (Challenge ID: 243)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Automation & Cryptographic Hashing
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** Beginner picoMini 2022
- **Points:** 40
- **Flag:** `academy{4ppl1c4710n_r3c31v3d_467e06bf}`

---

## Problem Statement & Scope
Peserta diminta menyelesaikan wawancara kerja simulasi pada layanan TCP socket. Server memberikan sejumlah string acak secara berurutan dan meminta kandidat menghitung hash MD5 dari teks tersebut dalam batas waktu ketat sebelum menyerahkan penawaran pekerjaan beserta flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Fungsi Hash Satu Arah (MD5):** MD5 (*Message-Digest Algorithm 5*) memetakan input pesan berukuran arbitrer menjadi representasi hash 128-bit (32 karakter heksadesimal). Sifat komputasinya deterministik: string identik selalu menghasilkan nilai hash yang sama.
2. **Kebutuhan Automasi Soket Jaringan:** Karena jeda waktu yang diberikan server sangat singkat dan teks yang diberikan acak pada setiap sesi, perhitungan manual mustahil dilakukan secara konsisten. Diperlukan skrip otomasi pemrograman socket interaktif untuk membaca string input, menghitung hash secara *real-time*, dan mengembalikan respon.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Sambungkan ke instance socket:
   ```bash
   nc chatelaine.cylabacademy.net 10485
   ```
2. Prompt server meminta:
   ```text
   Please md5 hash the text between quotes, excluding the quotes: 'Katharine Hepburn'
   Answer:
   ```
3. Bangun skrip Python interaktif untuk mengotomasi loop pertanyaan:
   ```python
   import socket, hashlib, re

   s = socket.socket()
   s.connect(("chatelaine.cylabacademy.net", 10485))
   for _ in range(10):
       buf = s.recv(1024).decode()
       if "academy{" in buf:
           print(re.search(r"academy\{[^}]+\}", buf).group(0))
           break
       m = re.search(r"[\x27\"]([^\x27\"]+)[\x27\"]", buf)
       if m:
           h = hashlib.md5(m.group(1).encode()).hexdigest()
           s.sendall(f"{h}\n".encode())
   ```
4. Setelah 3 jawaban benar berturut-turut, server mencetak:
   $$\text{academy\{4ppl1c4710n\_r3c31v3d\_467e06bf\}}$$

---

## Flag & Verifikasi
- **Flag:** `academy{4ppl1c4710n_r3c31v3d_467e06bf}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Otomasi Scripting Interaktif (Python Sockets):** Penguasaan modul `socket` bawaan Python untuk menangani handshake, ekstraksi regex dinamis, dan pengiriman payload cepat adalah senjata penting dalam modul *Speed Challenge* LKS Cyber Security.
- **Kerapuhan MD5 untuk Verifikasi Integritas/Sandi:** Meskipun digunakan dalam latihan dasar, algoritma MD5 telah rentan terhadap serangan tabrakan hash (*collision attack*). Dalam sistem produksi dan forensik digital, gunakan keluarga SHA-2 (SHA-256) atau SHA-3.
