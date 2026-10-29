# 756 Failure Failure (picoCTF 2026, General Skills, Medium)

## Challenge Metadata
- ID: 756 | Nama: Failure Failure | Event: picoCTF 2026
- Kategori: General Skills | Tingkat: Medium
- Flag: `academy{f41l0v3r_f0r_7h3_w1n_7897afd6}`
- Verifikasi: POST /api/submissions/ -> `{"correct": true}`

## Problem Statement & Scope
Sistem high-availability: HAProxy di depan dua backend Flask.
`s1` primer menjawab "No flag in this service" (env `IS_BACKUP` kosong);
`s2` backup (`IS_BACKUP=yes`) memegang flag. Health check
`GET /` expect 200, `fall 2 rise 3`, interval 2 detik.

## Teori & Akar Kerentanan (Root Cause)
Flask-Limiter memakai key function KONSTAN (`return "global"`) sehingga
SEMUA klien berbagi satu bucket 300/menit, termasuk health check milik
load balancer sendiri. Beban >5 req/s membuat `s1` menjawab 503
("Service Unavailable: Rate limit exceeded"), sehingga HAProxy
menandainya DOWN dan failover ke `s2`. Ini interaksi dua mekanisme yang
masing-masing benar (rate limit + failover) tetapi komposisinya membuka
jalur akses ke backend cadangan. Pola nyata: shared/global rate-limit key
dan health check yang tidak di-exempt dari throttling.

## Rekonstruksi Pengujian Terstruktur
1. Luncurkan lab: `PUT /api/challenges/756/instance/`, parse URL frontend.
2. Unduh `haproxy.cfg` + `app.py` dari CDN, petakan primer/backup.
3. Konfirmasi primer: `GET /` -> "No flag in this service".
4. Uji coba gagal: burst 400 paralel (limiter pulih, primer kembali);
   slowloris 55 koneksi (health check internal tak terpengaruh).
5. Temuan kunci: banjir 20 detik -> 503 massal = limiter global habis di
   `s1`, failover terjadi, tetapi banjir lanjutan ikut menghabiskan
   limiter `s2` (keduanya DOWN).
6. Strategi akhir: loader ~5.5 req/s sustained + poller 1 req/detik
   selama jendela 240 detik; poll ke-65 menangkap
   `academy{f41l0v3r_f0r_7h3_w1n_7897afd6}` dari `s2`.
7. Submit: `POST /api/submissions/` -> `correct: true`.

## Flag & Verifikasi
- Flag: `academy{f41l0v3r_f0r_7h3_w1n_7897afd6}` (native, format komunitas).
- Bukti: respons API `{"user": 1072359, "challenge": 756, "correct": true}`.

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Rate limit per-client (key = IP / token), jangan satu bucket global.
- Exempt health-check endpoint (`/healthz` tanpa limiter) dari throttling,
  atau monitor berbasis status backend bukan sekadar HTTP 200.
- Backup tier harus punya kontrol akses setara primer (defense in depth:
  flag hanya untuk sesi terotorisasi, bukan sekadar "siapa yang nyasar").
- Latihan LKS: baca `haproxy.cfg` (fall/rise/inter, kata kunci backup)
  dan petakan strategi failover dalam <5 menit.
