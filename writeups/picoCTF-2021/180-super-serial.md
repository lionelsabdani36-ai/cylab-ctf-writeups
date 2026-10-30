# 180 — Super Serial (picoCTF 2021, Web Exploitation, Medium)

## Challenge Metadata
- ID: 180 | Event: picoCTF 2021 | Author: (CyLab Academy)
- Kategori: Web Exploitation | Difficulty: Medium (2)
- Flag: `academy{1_c4nn0t_s33_y0u_cf804c42}`
- Status: SOLVED (POST /api/submissions/ -> `correct: true`)

## Problem Statement & Scope
Lab web on-demand (Apache 2.4 + PHP 8.2): halaman login `index.php`
(username/password, SQLite `../users.db`) dan `authentication.php`
(Welcome guest/admin). Petunjuk: flag ada di `../flag`. Source tersedia
via `.phps` (`index.phps`, `cookie.phps`, `authentication.phps`;
robots.txt menunjuk `/admin.phps` yang tidak ada).

## Teori & Akar Kerentanan (Root Cause)
PHP Object Injection lewat cookie `login` yang tidak diautentikasi:
`cookie.php` di-include setiap halaman dan langsung
`unserialize(base64_decode(urldecode($_COOKIE["login"])))` TANPA verifikasi
tanda tangan/HMAC. Kelas `access_log` (authentication.php) punya gadget
`__toString()` -> `read_log()` -> `file_get_contents($this->log_file)`.
Pemicu: `cookie.php` memanggil `$perm->is_guest()` pada objek hasil
unserialize; objek `access_log` tidak punya method itu -> `Error` ->
blok `catch(Error)` mengeksekusi `die("Deserialization error. ".$perm)`,
dan konkatenasi string memicu `__toString`, sehingga file arbitrari
(`../flag`) dibaca dan dicetak. CWE-502 (Deserialization of Untrusted
Data). Fakta live: `../users.db` hilang di instance sehingga login normal
selalu fatal — jalur injeksi cookie langsung adalah satu-satunya rute,
dan hanya `/authentication.php` yang merender flag (index.php fatal lebih
dulu di `require_once` karena `__PHP_Incomplete_Class` tidak bisa
di-stringify di luar blok try).

## Rekonstruksi Pengujian Terstruktur
1. Launch instance (`PUT /api/challenges/180/instance/`), parse URL web
   dari description (`http://xebec.cylabacademy.net:25954/`).
2. Rekon: `/` = form login; traversal langsung (`/../flag`, encoded,
   `/static/../flag`) ditolak Apache (400/404); `SQLite3('../users.db')`
   fatal (DB hilang).
3. Unduh source via `.phps`: `index.phps` (alir login + cookie),
   `cookie.phps` (unserialize + try/catch), `authentication.phps`
   (kelas `access_log` + gadget `__toString`).
4. Rakit cookie: `O:10:"access_log":1:{s:8:"log_file";s:7:"../flag";}`
   -> base64 -> urlencode -> `Cookie: login=...`.
5. `GET /authentication.php` dengan cookie -> respons:
   `Deserialization error. academy{1_c4nn0t_s33_y0u_cf804c42}`.
6. Submit via `POST /api/submissions/` -> `correct: true`.

## Flag & Verifikasi
- Flag resmi: `academy{1_c4nn0t_s33_y0u_cf804c42}`
- Verifikasi: `201 {"challenge": 180, "correct": true, "historical": false}`

## Takeaway Kompetensi LKS & Mitigasi Defensif
- JANGAN pernah `unserialize()` input user; gunakan JSON + HMAC
  (`hash_hmac`) atau session server-side. CWE-502 adalah vektor RCE/LFI
  klasik di CTF Web.
- `__toString` + file API = gadget baca file; audit semua magic method
  (`__wakeup`, `__destruct`, `__toString`) pada kode yang reachable.
- Jangan expose source via `.phps`/backup di produksi; robots.txt tidak
  boleh membocorkan path admin.
- Solver reproduktif: `scripts/solve_180_super_serial.py` (butuh instance
  RUNNING; kode identik dengan perintah live yang terverifikasi).
