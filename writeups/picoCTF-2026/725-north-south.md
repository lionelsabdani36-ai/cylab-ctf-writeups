# 725 - North-South (Web Exploitation, picoCTF 2026, Medium)

## Challenge Metadata
- ID: 725 | Event: picoCTF 2026
- Category: Web Exploitation | Difficulty: Medium (2)
- Author: picoCTF
- Flag: `academy{g30_b453d_r0u71n9_5e58725f}`

## Problem Statement & Scope
Layanan web `North-South` mengimplementasikan pembatasan akses geografis (*geo-based routing*). Permintaan dari sebagian besar region dialihkan ke kluster default yang hanya menampilkan halaman kosong (*"No flag in this region!"*). Hanya permintaan dari negara tertentu yang dirutekan ke upstream internal yang menyimpan flag rahasia.
Tersedia berkas konfigurasi Nginx resmi (`nginx.conf`). Objektif audit (NIST SP 800-115 / OWASP WSTG-CONF-05): menganalisis aturan routing geolokasi, mengidentifikasi region target, melakukan tunneling egress ke yurisdiksi yang dipersyaratkan, dan mengamankan flag.

## Teori & Akar Kerentanan (Root Cause)
1. **Nginx GeoIP2 Database Lookup Architecture:**
   Berkas `nginx.conf` menggunakan modul dinamis `ngx_http_geoip2_module.so` dengan basis data MaxMind `GeoLite2-Country.mmdb`:
   ```nginx
   geoip2 /etc/nginx/GeoLite2-Country.mmdb {
       auto_reload 5m;
       $geoip2_data_country_code default=ZZ country iso_code;
   }
   ```
2. **Conditional Upstream Routing:**
   Blok `server` mengevaluasi variabel ISO country code:
   ```nginx
   location / {
       if ($geoip2_data_country_code = IS) {
           proxy_pass http://south;
       }
       proxy_pass http://north;
   }
   ```
   Kode `IS` merujuk pada **Islandia (Iceland)**. Jika klien berasal dari Islandia, trafik dialihkan ke `upstream south` (`127.0.0.1:9000`), sedangkan IP lainnya diteruskan ke `upstream north` (`127.0.0.1:8000`).
3. **Absence of Header-Based GeoIP Spoofing:**
   Konfigurasi tidak memuat direktif `real_ip_header X-Forwarded-For` atau `set_real_ip_from`. Akibatnya, modul GeoIP2 membaca IP klien secara langsung dari socket layer `$remote_addr`. Manipulasi header HTTP (`X-Forwarded-For`, `Client-IP`, `CF-Connecting-IP`) diabaikan oleh Nginx, mengharuskan koneksi TCP riil berasal dari rentang IP Islandia.

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis `nginx.conf`:
   - Teridentifikasi dependensi upstream `south` pada kode negara ISO `IS` (Iceland).
2. Uji coba manipulasi header HTTP:
   - Mengirim request dengan header `X-Forwarded-For: 193.4.152.1` (IP University of Iceland).
   - Respons tetap: *"No flag in this region!"* — membuktikan evaluasi berbasis socket `$remote_addr`.
3. Membangun Sirkuit Egress Islandia via Tor:
   - Mengonfigurasi Tor proxy lokal pada port 9055 dengan pembatasan simpul keluar (*exit node*) ke wilayah Islandia:
     ```
     SocksPort 9055
     DataDirectory /tmp/tordata
     ExitNodes {is}
     StrictNodes 1
     ```
   - Verifikasi egress node via `curl --socks5 127.0.0.1:9055 https://ipinfo.io/json`:
     ```json
     {
       "ip": "185.112.144.11",
       "hostname": "iceland-tor.exit.maxzrbn.it",
       "city": "Reykjavík",
       "country": "IS"
     }
     ```
4. Eksfiltrasi Flag:
   - Melakukan request HTTP ke lab instance `http://xebec.cylabacademy.net:42790/` melalui proxy SOCKS5 Islandia:
     `curl --socks5 127.0.0.1:9055 http://xebec.cylabacademy.net:42790/`
   - Nginx memvalidasi `$geoip2_data_country_code = IS` dan meneruskan request ke upstream `south`.
   - Respons mengembalikan flag:
     `<p>academy{g30_b453d_r0u71n9_5e58725f}</p>`.
5. Verifikasi dan pembersihan:
   - Mengirim token flag ke REST API `POST /api/submissions/` -> HTTP 201 `correct: true`.
   - Mematikan daemon tor dan terminasi instance lab via `DELETE /api/challenges/725/instance/`.

## Flag & Verifikasi
- Flag: `academy{g30_b453d_r0u71n9_5e58725f}` (HTTP 201 `correct: true`, user 1072359).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Inadequacy of Geo-Blocking as Security Control:** Pemblokiran geografis (*Geo-fencing*) bukan kontrol keamanan batas (*perimeter security control*) yang memadai karena penyerang dapat dengan mudah mem-bypass melalui VPN komersial, VPS perumahan, proxy perantara, atau jaringan Tor.
- **Zero Trust Architecture (ZTA):** Otorisasi akses ke data atau layanan sensitif harus diverifikasi berbasis identitas pengguna yang kuat (autentikasi kriptografis, mTLS, FIDO2/WebAuthn), bukan atribut jaringan yang dapat dipindahkan seperti IP address atau lokasi MaxMind GeoIP.
- **WAF & Egress Reputation Filtering:** Jika restriksi wilayah diwajibkan oleh regulasi kepatuhan data (GDPR/residency), pasangkan GeoIP dengan feed ancaman reputasi IP yang memblokir secara aktif exit node Tor, proxy publik, dan hosting ASNs untuk mencegah bypass geolokasi.
