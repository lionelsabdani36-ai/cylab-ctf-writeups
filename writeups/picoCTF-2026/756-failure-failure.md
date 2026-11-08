# Writeup: Failure Failure (Challenge ID: 756)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / High-Availability Failover & Shared Rate-Limiting (NIST SP 800-115 §4.2)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** Darkraicg492
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{f41l0v3r_f0r_7h3_w1n_7897afd6}`
- **Flag Komunitas:** `CTF{f41l0v3r_f0r_7h3_w1n_7897afd6}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan audit infrastruktur ketersediaan tinggi (*High Availability / HA*) dan analisis anomali komposisi kebijakan kontrol lalu lintas jaringan:
> *"Welcome to **Failure Failure** — a high-available system. This challenge simulates a real-world failover scenario where one server is prioritized over the other. A load balancer stands between you and the truth — and it won't hand over the flag until you force its hand."*
> *Petunjuk: "Can you make the primary server fail gracefully?"*

Arsitektur sistem menggunakan *reverse proxy load balancer* HAProxy di lapisan terdepan yang mendistribusikan lalu lintas HTTP ke dua instans server aplikasi backend Flask:
1. **Primary Server (`s1` pada port 8000):** Menangani seluruh lalu lintas utama pengguna dalam kondisi normal. Variabel lingkungan `IS_BACKUP` tidak diaktifkan, sehingga aplikasi hanya merespons dengan pesan: `"No flag in this service"`.
2. **Backup Server (`s2` pada port 9000):** Dikonfigurasi dengan direktif `backup` pada HAProxy. Berjalan dengan variabel lingkungan `IS_BACKUP=yes` dan menyimpan token rahasia flag di memori lingkungan.

---

## Teori & Akar Kerentanan (Root Cause Theory)

Analisis konfigurasi HAProxy (`haproxy.cfg`) dan logika backend Flask (`app.py`) mengungkap kelemahan komposisi keamanan (*security composition flaw*):

1. **CWE-400 & CWE-653 / Ruang Lingkup Throttling Bersama (Monolithic Rate-Limiting Key):**
   - Backend Flask menerapkan pustaka `Flask-Limiter` untuk mencegah banjir permintaan dengan batasan kuota 300 permintaan per menit (`300 per minute`).
   - Namun, fungsi identifikasi klien (*key function*) ditetapkan secara konstan:
     ```python
     @limiter.limit("300 per minute", key_func=lambda: "global")
     ```
   - Akibatnya, seluruh klien di internet dan bahkan pemeriksaan kesehatan internal (*health check*) yang dikirimkan oleh load balancer HAProxy berbagi satu ember token (*shared token bucket*) yang sama.

2. **Kelemahan Komposisi Pemantauan Kesehatan (Health Check Starvation):**
   - Konfigurasi HAProxy menetapkan aturan pemantauan kesehatan berkala:
     ```haproxy
     option httpchk GET /
     http-check expect status 200
     server s1 backend1:8000 check inter 2s fall 2 rise 3
     server s2 backend2:9000 check backup inter 2s fall 2 rise 3
     ```
   - Setiap 2 detik (`inter 2s`), HAProxy mengirimkan permintaan `GET /` ke server `s1`. Jika respons berupa status kode selain 200 (seperti 503 saat kuota limiter terlampaui), pemeriksaan dianggap gagal.
   - Karena endpoint pemeriksaan kesehatan tidak dikecualikan (`exempt`) dari rate limiter, pembebanan lalu lintas eksternal yang melebihi 5 permintaan per detik ($> 300\text{ req/min}$) akan menghabiskan seluruh token rate limiter global pada `s1`.
   - Ketika HAProxy mengirimkan health check berikutnya, `s1` merespons dengan HTTP 503 (*"Service Unavailable: Rate limit exceeded"*).
   - Setelah 2 kali kegagalan berturut-turut (`fall 2`, sekitar 4 detik), HAProxy menandai `s1` sebagai `DOWN`.

3. **Mekanisme Pemicuan Pengalihan Beban (Failover Trigger):**
   - Begitu `s1` berstatus `DOWN`, HAProxy segera mengalihkan rute lalu lintas ke server cadangan `s2`.
   - Karena `s2` sebelumnya berstatus *standby* dan tidak menerima lalu lintas, ember token miliknya masih terisi penuh (sehat).
   - Permintaan HTTP yang masuk selama jendela transisi failover ini akan dilayani langsung oleh `s2`, mengekspos isi variabel `FLAG` kepada klien.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Reconnaissance Konfigurasi Infrastruktur:**
   - Menelaah berkas `haproxy.cfg` dan `app.py`:
     - Menemukan bahwa `s2` membawa flag saat `IS_BACKUP=yes`.
     - Parameter health check: `fall 2`, `inter 2s`, ekspektasi HTTP 200.
     - Rate limit `s1`: kuota 300 req/min dengan key `"global"`.

2. **Strategi Pembebanan Lalu Lintas Terukur (Calculated Throttling Starvation):**
   - Menjalankan thread pembebanan (*traffic loader thread*) dengan laju $\approx 5.5\text{ req/detik}$ (interval $\approx 0.18\text{ detik}$) untuk memastikan token habis tanpa memicu TCP connection reset.
   - Bersamaan dengan itu, menjalankan thread pemantau (*poller thread*) yang mengirimkan permintaan 1 kali per detik untuk menangkap transisi status HTTP.

3. **Pengamatan Transisi Status:**
   - Detik 0–3: Permintaan dilayani `s1` (HTTP 200: *"No flag in this service"*).
   - Detik 4–15: Token `s1` habis, klien mulai menerima HTTP 503. Health check HAProxy ikut terbentur limit dan menerima HTTP 503.
   - Detik 16: HAProxy mendeteksi `fall 2` berturut-turut pada `s1` dan memutasi status `s1` menjadi `DOWN`.
   - Detik 17: Lalu lintas dialihkan ke `s2`. Pemantau menerima HTTP 200 dari `s2` yang berisi token bendera:
     ```text
     Welcome to the Backup Server!
     Here is the flag: academy{f41l0v3r_f0r_7h3_w1n_7897afd6}
     ```

4. **Ekstraksi Token & Terminasi:**
   - Menangkap flag dan menghentikan pengiriman beban lalu lintas untuk memulihkan stabilitas container.
   - Skrip reproduktif terverifikasi: `scripts/solve_756_failure_failure.py`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{f41l0v3r_f0r_7h3_w1n_7897afd6}`
- **Format Flag Komunitas:** `CTF{f41l0v3r_f0r_7h3_w1n_7897afd6}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 756, "flag": "academy{f41l0v3r_f0r_7h3_w1n_7897afd6}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Segmentasi Identitas Klien pada Mekanisme Rate Limiting (CWE-653 Remediation):**
   - Jangan pernah menggunakan fungsi kunci statis/global untuk pembatasan laju (*rate limiting*).
   - Selalu gunakan identitas unik klien, seperti alamat IP asal (`get_remote_address`) yang dikombinasikan dengan header `X-Forwarded-For` terpercaya, atau token sesi terotentikasi.

2. **Isolasi Endpoint Pemantauan Kesehatan (Health Check Isolation):**
   - Pisahkan jalur pemantauan kesehatan load balancer ke endpoint khusus (misalnya `/healthz` atau `/ready`) dan kecualikan secara eksplisit dari pembatasan laju (`@limiter.exempt`).
   - Pertimbangkan penggunaan port manajemen internal atau soket Unix domain untuk health check agar terisolasi sepenuhnya dari antrean lalu lintas publik.

3. **Prinsip Pertahanan Berlapis pada Infrastruktur Cadangan (Defense-in-Depth for Backup Tiers):**
   - Server cadangan (*backup/failover instances*) tidak boleh mengasumsikan lingkungan aman hanya karena berada di balik mekanisme failover.
   - Kontrol akses, otorisasi data sensitif, dan kebijakan perlindungan rahasia harus diterapkan secara konsisten di seluruh lapisan primer maupun sekunder.
