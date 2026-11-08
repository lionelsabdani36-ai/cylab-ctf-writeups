# Writeup: Hashgate (Challenge ID: 750)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Insecure Direct Object References (IDOR) & Broken Access Control (NIST SP 800-115 §4.3)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** Yahaya Meddy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{id0r_unl0ck_cbbb8f45}`
- **Flag Komunitas:** `CTF{id0r_unl0ck_cbbb8f45}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan audit kontrol otorisasi aplikasi web dan identifikasi kerentanan IDOR (Insecure Direct Object Reference):
> *"You have gotten access to an organisation's portal. Submit your email and password, and it redirects you to your profile. But be careful: just because access to the admin isn’t directly exposed doesn’t mean it’s secure. Maybe someone forgot that obscurity isn’t security...*
> *Can you find your way into the admin’s profile for this organisation and capture the flag?"*

Aplikasi target adalah portal direktori profil organisasi. Halaman login menerima payload JSON berupa `email` dan `password`, kemudian melakukan pengalihan (*HTTP 302 Redirect*) ke URL spesifik pengguna:
`/profile/user/<hash>`.
Pada kode sumber HTML halaman muka, terdapat komentar pengembang yang membocorkan kredensial akun tamu (*Information Exposure in Comments*, CWE-615):
`guest@cylabacademy.org` / `guest`.

Setelah berhasil login sebagai tamu, pengguna diarahkan ke:
`/profile/user/e93028bdc1aacdfb3687181f2031765d`.
Sistem tidak mengeluarkan cookie sesi autentikasi maupun header otorisasi Bearer. Akses terhadap data profil sepenuhnya bertumpu pada URL hash tersebut (*Security by Obscurity*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Insecure Direct Object Reference (CWE-639 / OWASP A01:2021 - Broken Access Control):**
   - Kerentanan IDOR terjadi ketika aplikasi menyediakan akses langsung ke objek internal (rekaman profil pengguna di basis data) berdasarkan identifier yang diberikan pengguna atau terdapat pada parameter rute URL tanpa memvalidasi apakah pemohon memiliki hak akses yang sah atas objek tersebut.
   - Endpoint `/profile/user/<hash>` melayani data profil siapapun tanpa memverifikasi sesi login pemanggil. Penyerang yang dapat memprediksi atau mengetahui hash akun lain dapat mengakses profil pengguna lain secara bebas.

2. **Penggunaan Hash Lemah Tanpa Salt (CWE-328 - Reversible/Predictable One-Way Hash):**
   - Identifier hash `e93028bdc1aacdfb3687181f2031765d` adalah digest MD5 dari string `"3000"`:
     $$\text{MD5}("3000") = \text{e93028bdc1aacdfb3687181f2031765d}$$
   - Karena ID internal pengguna menggunakan bilangan bulat berurutan (*sequential auto-incrementing integer*), ruang pencarian kandidat ID sangat kecil (hanya berkisar beberapa puluh hingga ribuan bilangan).
   - Penggunaan algoritma hash deterministik cepat (seperti MD5) tanpa salt unik (*per-user salt*) atau rahasia server (*HMAC key*) memungkinkan penyerang membuat tabel pra-komputasi (*pre-image generation*) untuk ribuan ID hanya dalam beberapa milidetik.

3. **Prinsip Security by Obscurity (CWE-656):**
   - Pengembang berasumsi bahwa string heksadesimal 32-karakter hasil hash MD5 cukup "acak" sehingga tidak dapat ditebak oleh pihak luar. Hal ini melanggar prinsip desain keamanan fundamental bahwa keamanan sistem tidak boleh bergantung pada kerahasiaan implementasi pengalamatan (*Kerckhoffs's Principle*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Reconnaissance & Ekstraksi Kredensial Tamu:**
   - Memeriksa sumber HTML halaman `/`:
     ```html
     <!-- Dev note: test portal using guest@cylabacademy.org / guest -->
     ```
   - Mengirimkan permintaan login via JSON POST:
     ```bash
     curl -s -X POST -H "Content-Type: application/json" \
          -d '{"email":"guest@cylabacademy.org","password":"guest"}' \
          http://chatelaine.cylabacademy.net:23454/login
     ```
   - Server mengembalikan pengalihan menuju rute `/profile/user/e93028bdc1aacdfb3687181f2031765d`.

2. **Analisis Pola Hash Identifier:**
   - Memeriksa pola hash `e93028bdc1aacdfb3687181f2031765d`:
     - Panjang string: 32 karakter heksadesimal (karakteristik MD5).
     - Menghitung kecocokan terhadap integer berurutan:
       `hashlib.md5(b"3000").hexdigest() == "e93028bdc1aacdfb3687181f2031765d"`.
     - Konfirmasi: Hash berasal dari string representasi ID pengguna (`3000`).

3. **Eksekusi Serangan IDOR (Enumerasi ID Karyawan & Admin):**
   - Melakukan loop enumerasi ID integer di sekitar ID tamu (range 2980 hingga 3030):
     - ID 3000: Guest profile.
     - ID 3001: Staff profile.
     - ...
     - ID 3010: Menghasilkan hash MD5 `22722a343513ed45f14905eb07621686`.
   - Mengirimkan permintaan HTTP GET ke endpoint:
     `GET /profile/user/22722a343513ed45f14905eb07621686`.
   - Respons server memuat halaman profil administrator:
     ```html
     <h1>Welcome, admin!</h1>
     <p>Here is the flag: academy{id0r_unl0ck_cbbb8f45}</p>
     ```

4. **Otomasi Reproduktif & Submisi REST API:**
   - Skrip mandiri diimplementasikan pada `scripts/solve_750_hashgate.py` dengan simulator lokal dan fungsi eksploitasi live.
   - Submisi token verifikasi ke CyLab REST API `POST /api/submissions/` berhasil mengonfirmasi status `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{id0r_unl0ck_cbbb8f45}`
- **Format Komunitas:** `CTF{id0r_unl0ck_cbbb8f45}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 750, "flag": "academy{id0r_unl0ck_cbbb8f45}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Implementasi Kontrol Akses Berbasis Sesi (CWE-639 Remediation):**
   - Setiap permintaan data profil pengguna wajib melalui lapisan otorisasi server-side (*Server-Side Authorization Gate*).
   - Validasi bahwa sesi pengguna yang sedang login (`session['user_id']`) identik dengan ID profil yang diminta, atau pengguna memiliki peran administratif (*Role-Based Access Control* / RBAC):
     ```python
     if current_user.id != requested_profile_id and not current_user.is_admin:
         abort(403, "Access Denied: Unauthorized resource access")
     ```

2. **Penggunaan Cryptographically Secure Identifiers (UUIDv4):**
   - Hindari mengekspos identifier sekuensial atau hash langsung dari integer sederhana ke lapisan URL publik.
   - Gunakan Universally Unique Identifier versi 4 (UUIDv4) yang dibuat oleh CSPRNG sebagai ID eksternal publik, dan tetap terapkan verifikasi sesi pada setiap pemanggilan rute.

3. **Pembersihan Metadata & Kepatuhan NIST SP 800-53 AC-3 (Access Enforcement):**
   - Hapus seluruh komentar kode pengembang, catatan pengujian, dan kredensial default dari berkas template produksi (mitigasi CWE-615).
   - Terapkan pembatasan laju (*Rate Limiting*) pada endpoint pencarian profil untuk mendeteksi dan memblokir upaya automated scraping/scanning.

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)

- **David (Leader):** Mengarahkan strategi analisis kontrol akses aplikasi web dan memvalidasi kepatuhan metodologi pengujian penetrasi NIST SP 800-115 §4.3.
- **Charlie (Trend-hunter):** Mengidentifikasi tingginya frekuensi kemunculan soal kategori OWASP Top 10 A01 (Broken Access Control & IDOR) dalam kompetisi LKS Cyber Security Nasional.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Mengembangkan skrip solver otomasi IDOR dengan kalkulasi hash pre-image MD5 dan simulator profil backend lokal.
- **Julius (QA-engineer):** Memvalidasi keberhasilan pemulihan flag pada ID 3010 dan memastikan respons status HTTP 201 pada platform verifikasi CyLab.
- **Athena (Security-engineer):** Meninjau celah otorisasi CWE-639 / CWE-328 dan merancang arsitektur RBAC defensif sesuai NIST SP 800-53 AC-3.
- **Judith (Guru LKS):** Mengintegrasikan skenario eksploitasi IDOR ke dalam modul bimbingan teknis persiapan lomba siswa LKS untuk modul *Web Security & Incident Response*.
