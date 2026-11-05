# Writeup: where are the robots (Challenge ID: 4)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Information Disclosure via Robots Exclusion Standard (RFC 9309)
- **Difficulty:** Easy (diff=1)
- **Author:** zarhack
- **Event:** picoCTF 2019
- **Points:** 100
- **Flag:** `academy{ca1cu1at1ng_Mach1n3s_5ed99}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman terhadap mekanisme standar perayapan web (web crawler / robot indexing):
> *"Can you find the robots? `http://<host>:<port>`"*
>
> Petunjuk:
> *"What part of the website could tell you where the creator doesn't want you to look?"*

Lingkup investigasi mencakup penelusuran berkas konfigurasi publik pada root direktori web server yang mengatur kebijakan perayapan bot pencarian (*search engine web spiders*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Standar Eksklusi Robot (Robots Exclusion Protocol / RFC 9309):**
   - Berkas `/robots.txt` adalah berkas teks sederhana yang ditempatkan pada root domain web server untuk memberikan instruksi kepada bot pencari (seperti Googlebot, Bingbot) mengenai direktori atau berkas yang diizinkan (`Allow`) atau dilarang (`Disallow`) untuk diindeks.
   - Perlu ditekankan bahwa berkas `robots.txt` **bukanlah mekanisme kontrol akses atau otentikasi**. Berkas tersebut dapat dibaca secara publik oleh siapa pun melalui permintaan HTTP biasa (`GET /robots.txt`).

2. **Pengungkapan Informasi Sensitif (CWE-200 / Security through Obscurity):**
   - Menaruh rute administratif tersembunyi, direktori rahasia, atau berkas internal pada direktori `Disallow` secara tidak sengaja justru mempublikasikan peta aset sensitif (*attack surface reconnaissance*) kepada penyerang.
   - Berdasarkan panduan **NIST SP 800-115** (*Section 5.2: Web Application Security Review*), direktori terlarang tidak boleh hanya disembunyikan lewat `robots.txt`, melainkan wajib dilindungi menggunakan kontrol otorisasi kuat di tingkat server web atau lapisan aplikasi (misalnya HTTP Basic Auth, RBAC, atau pembatasan IP).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inisialisasi Container Lab On-Demand:**
   - Luncurkan container lab via `PUT /api/challenges/4/instance/`.
   - Peroleh endpoint web aktif (`http://chatelaine.cylabacademy.net:42899`).

2. **Inspeksi Berkas `/robots.txt`:**
   Kirimkan permintaan HTTP GET ke endpoint `/robots.txt`:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:42899/robots.txt
   ```
   Server mengembalikan konten instruksi:
   ```text
   User-agent: *
   Disallow: /5ed99.html
   ```

3. **Akses ke Jalur Tersembunyi (Disallowed Path):**
   Navigasikan permintaan ke rute yang tercantum pada direktori `Disallow`:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:42899/5ed99.html
   ```
   Halaman merespons dengan konten HTML:
   ```html
   <!doctype html>
   <html>
     <head>
       <title>Where are the robots</title>
       <link href="https://fonts.googleapis.com/css?family=Monoton|Roboto" rel="stylesheet">
       <link rel="stylesheet" type="text/css" href="style.css">
     </head>
     <body>
       <div class="container">
         <div class="content">
           <p>Guess you found the robots<br />
             <flag>academy{ca1cu1at1ng_Mach1n3s_5ed99}</flag></p>
         </div>
         <footer></footer>
     </body>
   </html>
   ```

4. **Ekstraksi Flag:**
   Tag `<flag>` menampilkan flag resmi:
   `academy{ca1cu1at1ng_Mach1n3s_5ed99}`

---

## Flag & Verifikasi

- **Flag:** `academy{ca1cu1at1ng_Mach1n3s_5ed99}`
- **Verifikasi API CyLab:**
  Submisi HTTP POST langsung ke `/api/submissions/`:
  ```json
  {"challenge": 4, "flag": "academy{ca1cu1at1ng_Mach1n3s_5ed99}"}
  ```
  Status respons: `HTTP 201 Created` dengan `{"correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Pemisahan Antara Crawling Policy dan Access Control:**
   - Jangan pernah mengandalkan berkas `robots.txt` untuk mengamankan halaman privat, panel admin, atau dokumen rahasia.
   - Jika suatu rute tidak boleh diakses oleh publik, terapkan proteksi otentikasi (misal sesi JWT, OAuth, atau pembatasan firewall/WAF) sehingga setiap permintaan tanpa kredensial valid akan mengembalikan `HTTP 401 Unauthorized` atau `403 Forbidden`.

2. **Penggunaan Tag Header `X-Robots-Tag` & `noindex`:**
   - Untuk mencegah mesin pencari mengindeks halaman tertentu tanpa membeberkan path di `robots.txt`, kirimkan HTTP header:
     ```http
     X-Robots-Tag: noindex, nofollow
     ```
     atau meta tag di dalam head HTML:
     ```html
     <meta name="robots" content="noindex, nofollow">
     ```
