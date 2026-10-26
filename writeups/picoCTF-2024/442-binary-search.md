# Writeup: Binary Search (Challenge ID: 442)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Algorithm Design & Shell Automation
- **Difficulty:** Easy
- **Author:** Jeffery John
- **Event:** picoCTF 2024
- **Points:** 100
- **Flag:** `academy{g00d_gu355_8d52ff5b}`

---

## Problem Statement & Scope
Disediakan sebuah layanan shell interaktif berbasis SSH yang menjalankan permainan tebak angka ("Binary Search Game"). Sistem memilih satu bilangan acak antara 1 hingga 1000 dan memberikan batas maksimal 10 kali kesempatan menebak. Peserta diminta menemukan angka rahasia tersebut untuk memperoleh flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kompleksitas Waktu Algoritma Pencarian Biner (Binary Search):**
   Pencarian linier memerlukan waktu $O(N)$ yang dalam skenario terburuk membutuhkan 1000 tebakan (jauh melampaui kuota 10 tebakan). Sebaliknya, algoritma pencarian biner memiliki kompleksitas $O(\log_2 N)$. Untuk rentang $N = 1000$:
   $$\lceil \log_2(1000) \rceil = \lceil 9.965 \rceil = 10 \text{ tebakan}$$
   Artinya, dengan membagi ruang pencarian menjadi separuh pada setiap langkah ($\text{mid} = \lfloor \frac{\text{low} + \text{high}}{2} \rfloor$), angka berapapun pasti dapat ditemukan dalam maksimal 10 tebakan.
2. **Kebutuhan Otomasi PTY / Shell Interaktif:** Permainan dijalankan melalui sesi SSH yang membutuhkan penanganan input/output interaktif secara dinamis berdasarkan umpan balik `Higher!` atau `Lower!`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis koneksi SSH instance:
   ```bash
   ssh -p 33348 ctf-player@chatelaine.cylabacademy.net
   # Password: <PASSWORD>
   ```
2. Rancang skrip otomasi Python interaktif menggunakan `subprocess` dan `sshpass`:
   ```python
   import subprocess, re

   cmd = ["sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no", "-tt", "-p", str(port), f"ctf-player@{host}"]
   proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)

   low, high = 1, 1000
   buf = ""
   while True:
       char = proc.stdout.read(1).decode(errors="ignore")
       buf += char
       if "Enter your guess: " in buf:
           mid = (low + high) // 2
           proc.stdin.write(f"{mid}\n".encode())
           proc.stdin.flush()
           buf = ""
       elif "Lower!" in buf:
           high = mid - 1
           buf = ""
       elif "Higher!" in buf:
           low = mid + 1
           buf = ""
       elif "academy{" in buf:
           # Capture remaining flag string
           ...
   ```
3. Eksekusi alur pencarian:
   - Tebakan 1: Rentang `[1, 1000]`, tebak `500` $\rightarrow$ `Lower!` (Rentang baru `[1, 499]`)
   - Tebakan 2: Rentang `[1, 499]`, tebak `250` $\rightarrow$ `Lower!` (Rentang baru `[1, 249]`)
   - Tebakan 3: Rentang `[1, 249]`, tebak `125` $\rightarrow$ `Higher!` (Rentang baru `[126, 249]`)
   - Tebakan 4: Rentang `[126, 249]`, tebak `187` $\rightarrow$ `Lower!` (Rentang baru `[126, 186]`)
   - Tebakan 5: Rentang `[126, 186]`, tebak `156` $\rightarrow$ `Higher!` (Rentang baru `[157, 186]`)
   - Tebakan 6: Rentang `[157, 186]`, tebak `171` $\rightarrow$ `Higher!` (Rentang baru `[172, 186]`)
   - Tebakan 7: Rentang `[172, 186]`, tebak `179` $\rightarrow$ `Lower!` (Rentang baru `[172, 178]`)
   - Tebakan 8: Rentang `[172, 178]`, tebak `175` $\rightarrow$ `Higher!` (Rentang baru `[176, 178]`)
   - Tebakan 9: Rentang `[176, 178]`, tebak `177` $\rightarrow$ `Lower!` (Rentang baru `[176, 176]`)
   - Tebakan 10: Tebak `176` $\rightarrow$ Benar!
4. Program mencetak flag:
   ```text
   Congratulations! You guessed the correct number!
   Here is your flag: academy{g00d_gu355_8d52ff5b}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{g00d_gu355_8d52ff5b}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Penerapan Algoritma Pencarian Efisien pada Keamanan:** Binary search digunakan secara luas dalam *blind SQL injection*, *side-channel timing attacks*, dan *memory offset discovery* untuk memulihkan data byte-demi-byte dengan jumlah permintaan minimal.
- **Rate-Limiting & Anti-Automation:** Layanan sensitif (seperti formulir login atau reset PIN) wajib menerapkan rate-limiting ketat (maksimal 3-5 percobaan sebelum lockout sementara) serta CAPTCHA untuk mencegah algoritma pencarian biner atau brute-force otomatis mengeksfiltrasi data.
