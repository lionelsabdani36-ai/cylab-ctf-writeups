# Writeup: Insp3ct0r (Challenge ID: 18)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Client-Side Source Inspection (HTML, CSS, JS)
- **Difficulty:** Easy (diff=1)
- **Author:** zarhack
- **Event:** picoCTF 2019
- **Points:** 50
- **Flag:** `academy{tru3_d3t3ct1ve_0r_ju5t_lucky?d6c61154}`

---

## Problem Statement & Scope

Tantangan menguji kemampuan dasar analisis kode sumber sisi klien (client-side static analysis):
> *"Kishor Balan tipped us off that the following code may need inspection: `http://<host>:<port>`"*
>
> Petunjuk:
> 1. Bagaimana cara memeriksa kode sumber web di browser?
> 2. Flag terbagi menjadi 3 bagian (There's 3 parts).

Lingkup pengujian mencakup peninjauan berkas frontend statis yang disajikan oleh server web: berkas markup HTML utama (`index.html`), lembar gaya visual CSS (`mycss.css`), dan skrip interaktif JavaScript (`myjs.js`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Penyimpanan Informasi Sensitif pada Komentar Kode Frontend (CWE-615):**
   - Komentar dalam kode HTML (`<!-- ... -->`), CSS (`/* ... */`), dan JavaScript (`//` atau `/* ... */`) tidak dirender secara visual pada tampilan halaman web standar, namun seluruh byte karakter komentar tersebut tetap dikirimkan ke browser pengguna (*delivered in plaintext over HTTP*).
   - Pengembang sering kali meninggalkan catatan internal, kunci API sementara, dokumentasi endpoint tersembunyi, atau struktur kredensial di dalam komentar file statis. Sesuai taksonomi kelemahan perangkat lunak, kondisi ini diklasifikasikan sebagai **CWE-615: Inclusion of Sensitive Information in Source Code Comments**.
   - Berdasarkan panduan **NIST SP 800-115** (*Section 5.2: Web Application Security Review*), audit kode web wajib memverifikasi bahwa pipeline build dan deployment secara otomatis melakukan *minification* dan *stripping* terhadap seluruh komentar pengembang sebelum artefak dipublikasikan ke lingkungan produksi.

2. **Ketiadaan Validasi / Keamanan Berbasis Obfuskasi Klien (Security through Obscurity):**
   - Menyembunyikan token rahasia di berbagai file statis yang berbeda (pemecahan flag menjadi 3 bagian) hanyalah bentuk obfuskasi pasif yang tidak memberikan perlindungan keamanan nyata. Setiap aset yang dapat diakses oleh browser klien berada di bawah kendali penuh inspeksi pengguna.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inisialisasi Container Lab On-Demand:**
   - Luncurkan container lab via `PUT /api/challenges/18/instance/`.
   - Peroleh endpoint layanan web aktif (`http://chatelaine.cylabacademy.net:42149`).

2. **Inspeksi Bagian 1/3 (HTML Source):**
   Mengambil halaman index dan memindai komentar HTML:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:42149/ | grep -i "flag"
   ```
   Ditemukan komentar markup:
   ```html
   <!-- Html is neat. Anyways have 1/3 of the flag: academy{tru3_d3 -->
   ```
   Fragmen 1: `academy{tru3_d3`

3. **Inspeksi Bagian 2/3 (Linked Stylesheet CSS):**
   Memeriksa berkas CSS yang ditautkan di dalam `<link rel="stylesheet" type="text/css" href="mycss.css">`:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:42149/mycss.css | grep -i "flag"
   ```
   Ditemukan komentar CSS:
   ```css
   /* You need CSS to make pretty pages. Here's part 2/3 of the flag: t3ct1ve_0r_ju5t */
   ```
   Fragmen 2: `t3ct1ve_0r_ju5t`

4. **Inspeksi Bagian 3/3 (Linked Script JS):**
   Memeriksa berkas JavaScript yang dimuat melalui `<script type="application/javascript" src="myjs.js"></script>`:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:42149/myjs.js | grep -i "flag"
   ```
   Ditemukan komentar JavaScript:
   ```javascript
   /* Javascript sure is neat. Anyways part 3/3 of the flag: _lucky?d6c61154} */
   ```
   Fragmen 3: `_lucky?d6c61154}`

5. **Penggabungan Token Utuh:**
   Menggabungkan ketiga fragmen berurutan:
   $$\text{Part 1} + \text{Part 2} + \text{Part 3} = \texttt{academy\{tru3\_d3} + \texttt{t3ct1ve\_0r\_ju5t} + \texttt{\_lucky?d6c61154\}} = \texttt{academy\{tru3\_d3t3ct1ve\_0r\_ju5t\_lucky?d6c61154\}}$$

---

## Flag & Verifikasi

- **Flag:** `academy{tru3_d3t3ct1ve_0r_ju5t_lucky?d6c61154}`
- **Verifikasi API CyLab:**
  Submisi HTTP POST langsung ke `/api/submissions/`:
  ```json
  {"challenge": 18, "flag": "academy{tru3_d3t3ct1ve_0r_ju5t_lucky?d6c61154}"}
  ```
  Status respons: `HTTP 201 Created` dengan `{"correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Penerapan Pipeline CI/CD Minification & Obfuscation:**
   - Dalam lingkungan pengujian LKS Cyber Security, modul defensif mensyaratkan pembersihan otomatis terhadap seluruh komentar pengembang dan debug statements sebelum rilis ke server produksi.
   - Gunakan bundler modern (seperti Vite, Webpack, esbuild, atau Terser) dengan opsi pembersihan komentar diaktifkan:
     ```javascript
     // Contoh konfigurasi Terser / Esbuild
     minify: true,
     legalComments: 'none'
     ```

2. **Pemberlakuan Kebijakan Secret Management:**
   - Tidak diperkenankan menaruh string sensitif, kredensial konfigurasi, atau token otentikasi di dalam bundel frontend statis.
   - Seluruh rahasia wajib dikelola di sisi backend dengan mekanisme *environment variables* yang aman dan tidak terekspos ke klien.
