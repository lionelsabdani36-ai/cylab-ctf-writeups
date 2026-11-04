# 436 - SansAlpha (General Skills, picoCTF 2024, Medium)

## Challenge Metadata
- ID: 436 | Event: picoCTF 2024
- Category: General Skills | Difficulty: Medium (2)
- Author: SYREAL
- Points: 200 Pts
- Flag: `academy{7h15_mu171v3r53_15_m4dn355_9b767f07}`

## Problem Statement & Scope
Pengguna diberikan akses remote shell interaktif via SSH ke server Linux target. Namun, lingkungan shell tersebut dibatasi secara ketat (*restricted shell*) di mana seluruh karakter alfabet (`[a-zA-Z]`) dilarang dan di-filter.
Deskripsi menyatakan:
*"The Multiverse is within your grasp! Unfortunately, the server that contains the secrets of the multiverse is in a universe where keyboards only have numbers and (most) symbols. hints: Where can you get some letters?"*

Objektif pengujian (NIST SP 800-115 / OWASP Top 10 A03:2021-Injection / CWE-78 OS Command Injection & Restricted Shell Escape):
Menganalisis mekanisme pembatasan karakter input shell, memanfaatkan variabel internal dan fitur evaluasi subshell Bash untuk merekonstruksi karakter alfabet tanpa menggunakan huruf literal, mengeksekusi pembacaan berkas sensitif `flag.txt`, dan memvalidasi token flag resmi.

## Teori & Analisis Arsitektur Kerentanan
1. **Restricted Shell Environment (`CWE-78`):**
   Sesi login SSH menjalankan wrapper script yang memeriksa setiap karakter perintah pengguna. Jika input mengandung karakter alfanumerik huruf (`[a-zA-Z]`), perintah langsung dibatalkan sebelum dieksekusi. Hanya karakter numerik (`0-9`) dan simbol (`$`, `_`, `{`, `}`, `:`, `*`, `/`, `"`, `'`, `.`, `\`) yang diizinkan.
2. **Bash Parameter Expansion & Special Variables:**
   - Dalam shell Bash, variabel khusus `$_` menyimpan argumen terakhir dari perintah sebelumnya.
   - Evaluasi subshell `$()` memungkinkan pengeksekusian perintah shell internal dan menangkap outputnya.
   - Perintah invalid seperti `"$(. 1 2>&1)"` mencoba melakukan operasi *source* (`.`) pada berkas `1`. Operasi ini gagal dan mencetak pesan galat ke aliran *stderr*:
     `bash: bash: 1: No such file or directory: command not found`
   - Melalui redireksi `2>&1`, pesan galat ini dievaluasi sebagai string perintah dan diteruskan ke variabel `$_`.
3. **Ekstraksi Karakter via Substring Slicing:**
   Bash mendukung sintaks manipulasi substring `${parameter:offset:length}`:
   - Index 14: Karakter `c` (dari kata `directory` atau `such`)
   - Index 1: Karakter `a` (dari kata `bash`)
   - Index 30: Karakter `t` (dari kata `directory` atau `not`)
   - Index 17: Karakter `f` (dari kata `file`)
   Dengan menggabungkan parameter tersebut:
   `${_:14:1}${_:1:1}${_:30:1}` menghasilkan perintah `cat`.
   `${_:17:1}` menghasilkan karakter `f`.
   Ekspresi `${_:14:1}${_:1:1}${_:30:1} */${_:17:1}*` dievaluasi oleh Bash menjadi `cat */f*`, yang mencocokkan berkas `blargh/flag.txt` di direktori kerja pengguna.

## Rekonstruksi Eksploitasi Step-by-Step
1. Tahap 1 — Probing Status & Inisiasi Kontainer Lab:
   - Mengaktifkan kontainer challenge melalui endpoint CyLab: `PUT /api/challenges/436/instance/`.
   - Mendapatkan alamat SSH: `ssh -p 47735 ctf-player@xebec.cylabacademy.net` dengan password `fa1a82ad`.
2. Tahap 2 — Koneksi & Interaksi PTY Shell:
   - Terhubung ke SSH server menggunakan pseudo-terminal (`pty`) dengan kredensial yang diberikan.
   - Shell merespons dengan prompt `SansAlpha$`.
3. Tahap 3 — Pembentukan String Error pada Variabel `$_`:
   - Mengirim perintah tanpa huruf:
     ```bash
     "$(. 1 2>&1)"
     ```
   - Shell mencetak galat:
     `bash: bash: 1: No such file or directory: command not found`
   - Variabel `$_` kini menyimpan string galat lengkap yang memuat karakter-karakter alfabet yang dibutuhkan.
4. Tahap 4 — Eksekusi Command Concatenation & Flag Recovery:
   - Mengirim payload slicing substring dan path globbing:
     ```bash
     ${_:14:1}${_:1:1}${_:30:1} */${_:17:1}*
     ```
   - Shell mengeksekusi `cat */f*` dan menampilkan isi berkas:
     `return 0 academy{7h15_mu171v3r53_15_m4dn355_9b767f07}`.
5. Tahap 5 — Validasi Platform:
   - Mengirim token flag ke REST API CyLab: `POST /api/submissions/` dengan payload:
     `{"challenge": 436, "flag": "academy{7h15_mu171v3r53_15_m4dn355_9b767f07}"}`.
   - Respons platform: `HTTP 201 Created` (`correct: true`, user 1072359).
   - Mengirim permintaan `DELETE /api/challenges/436/instance/` untuk membersihkan kontainer lab.

## Flag & Bukti Verifikasi
- Flag Resmi: `academy{7h15_mu171v3r53_15_m4dn355_9b767f07}`
- Bukti Validasi: REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created (`correct: true`, user 1072359).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Ketidakefektifan Blacklist Karakter:** Memfilter karakter alfabet tanpa mengisolasi lingkungan shell adalah mekanisme pertahanan yang rentan. Bash menyediakan kapabilitas ekspansi variabel, fungsi bawaan, dan substitusi proses yang kaya sehingga penyerang dapat menyusun karakter arbitrer.
- **Dedicated Application Sandboxing:** Jika layanan memerlukan eksekusi perintah terbatas, jangan sediakan shell Bash interaktif. Gunakan parser berbasis AST, perintah terisolasi via `rbash` dengan pembatasan direktori PATH yang ketat, atau gunakan protokol API RPC berbasis JSON yang tidak mengeksekusi shell interpreter sama sekali.
- **Prinsip Least Privilege & Filesystem Hardening:** Tempatkan berkas rahasia di luar jangkauan pembacaan pengguna shell reguler dan gunakan modul keamanan kernel Linux (AppArmor atau SELinux) untuk membatasi akses baca ke direktori kerja spesifik.