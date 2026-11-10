# Writeup: findme (Challenge ID: 349)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / HTTP Redirection Chains & Information Disclosure (CWE-200 / CWE-598)
- **Difficulty:** Medium (diff=2)
- **Event:** picoCTF 2023
- **Points:** 100
- **Author:** Mubarak Mikail
- **Flag Resmi:** `academy{proxies_all_the_way_661fc398}`
- **Standar Audit:** NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Verification)

---

## Problem Statement & Scope

Tantangan `findme` menyediakan sebuah aplikasi web berbasis Node.js Express yang mensimulasikan sistem perbankan daring. Halaman awal menyajikan formulir login (`/login`) dengan instruksi pengujian kredensial `test` dan kata sandi `test!`.

Ketika pengguna memasukkan kredensial yang diminta, peramban grafis secara otomatis dialihkan melalui beberapa halaman dan akhirnya mendarat di halaman beranda `/home` yang tampak seperti antarmuka demo perbankan biasa tanpa adanya bendera. Peserta dihadapkan pada petunjuk *"any redirections?"* untuk mengungkap informasi tersembunyi yang terlewatkan selama proses pengalihan otomatis berlangsung.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kebocoran Informasi pada Rantai Pengalihan HTTP (CWE-200 / RFC 7231):**
   Aplikasi memecah token bendera rahasia menjadi dua fragmen terpisah dan menyematkannya ke dalam parameter URI pada jalur pengalihan bertahap:
   - Fragmen 1 disematkan pada header HTTP `Location` dalam respon `302 Found` saat pengiriman formulir POST `/login`:
     `Location: /next-page/id=YWNhZGVteXtwcm94aWVzX2Fs`
   - Fragmen 2 disematkan pada skrip sisi klien (*client-side DOM JavaScript redirect*) pada badan HTML `/next-page/id=...`:
     `<script>window.location = '/next-page/id=bF90aGVfd2F5XzY2MWZjMzk4fQ==';</script>`
   - Halaman berikutnya segera mengalihkan sesi ke `/home`.

2. **Kelemahan Asumsi Perilaku Klien Otomatis (*Blind Follow-Redirect Pitfall*):**
   Klien HTTP otomatis atau peramban modern secara default mengikuti respon `302 Found` secara transparan tanpa menampilkan header perantara kepada pengguna akhir. Akibatnya, analis yang hanya mengamati halaman akhir `/home` tidak akan menemukan data sensitif.

3. **Pengkodean Base64 Bukan Merupakan Proteksi Kriptografis (CWE-312):**
   Kedua fragmen token hanya dienkode menggunakan skema Base64 standar tanpa kunci enkripsi atau tanda tangan kriptografis:
   - Fragmen 1: `YWNhZGVteXtwcm94aWVzX2Fs` -> `academy{proxies_al`
   - Fragmen 2: `bF90aGVfd2F5XzY2MWZjMzk4fQ==` -> `l_the_way_661fc398}`
   Penggabungan kedua segmen menghasilkan token bendera lengkap.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Alur Login Manual Menggunakan cURL Tanpa Opsi `-L`:**
   Lakukan permintaan POST ke `/login` dan hentikan peramban agar tidak otomatis mengikuti pengalihan:
   ```bash
   curl -i -s -X POST "http://<target_host>:<port>/login" \
     -d "username=test&password=test!"
   ```
   Amati header respon:
   ```http
   HTTP/1.1 302 Found
   Location: /next-page/id=YWNhZGVteXtwcm94aWVzX2Fs
   ```

2. **Inspeksi Badan HTML Halaman Perantara:**
   Kirimkan permintaan GET ke URI pengalihan pertama:
   ```bash
   curl -s "http://<target_host>:<port>/next-page/id=YWNhZGVteXtwcm94aWVzX2Fs"
   ```
   Ditemukan skrip pengalihan sisi klien:
   ```html
   <script>
     window.location = '/next-page/id=bF90aGVfd2F5XzY2MWZjMzk4fQ==';
   </script>
   ```

3. **Dekode dan Konkatenasi Token:**
   ```bash
   echo -n "YWNhZGVteXtwcm94aWVzX2Fs" | base64 -d
   # Output: academy{proxies_al

   echo -n "bF90aGVfd2F5XzY2MWZjMzk4fQ==" | base64 -d
   # Output: l_the_way_661fc398}
   ```
   Hasil akhir penggabungan string:
   `academy{proxies_all_the_way_661fc398}`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{proxies_all_the_way_661fc398}`
- **Status Submisi REST API:** HTTP 201 Created (`correct: true`, `historical: false`).
- **Skrip Solver:** `scripts/solve_349_findme.py` (eksekusi deterministik mandiri exit 0).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Metodologi Audit Intersepsi Lalu Lintas Web (NIST SP 800-115 § 4.2):**
   Peserta LKS Cyber Security bidang Web Application Security wajib menguasai penggunaan proxy intersepsi (seperti Burp Suite / OWASP ZAP) atau perintah utilitas jaringan tingkat rendah (`curl -v -D -`). Pengujian web tidak boleh hanya bergantung pada tampilan peramban GUI yang menyembunyikan status kode `3xx` dan header transportasi.

2. **Pencegahan Kebocoran Data Sensitif via URL Query Parameter (CWE-598):**
   Data rahasia, sesi, atau token autentikasi tidak boleh ditransmisikan melalui parameter URI atau jalur URL. Informasi dalam URL tercatat secara permanen pada log akses server web, proksi perantara, berkas riwayat peramban, dan header `Referer` (RFC 7231).

3. **Penerapan Pengalihan Sesi Aman (*Secure Session State Handling*):**
   Alihkan data sesi menggunakan penyimpanan sisi server (*server-side session storage*) yang terikat dengan cookie terenkripsi bertribut `HttpOnly`, `Secure`, dan `SameSite=Strict`. Jangan pernah mempercayakan integritas alur bisnis pada manipulasi parameter rute sisi klien.
