# Writeup: Wireshark doo dooo do doo... (Challenge ID: 115)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Network PCAP Packet Dissection & ROT13 Inversion
- **Difficulty:** Medium (diff=2)
- **Author:** Dylan
- **Event:** picoCTF 2021
- **Points:** 50
- **Flag:** `academy{p33kab00_1_s33_u_deadbeef}`

---

## Problem Statement & Scope

Tantangan menguji kemampuan investigasi lalu lintas jaringan dan analisis paket HTTP:
> *"Can you find the flag?"*
> Artefak: `shark1.pcapng`
> Deskripsi: Berkas tangkapan jaringan format PCAP Next Generation (PCAPNG) yang merekam aktivitas sesi TCP, HTTP, dan DNS lokal.

Peserta ditugaskan untuk membedah paket jaringan, mengekstraksi percakapan TCP/HTTP yang membawa transmisi teks polos atau string sandi, dan memulihkan flag resmi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Transmisi Teks Terang Tanpa Enkripsi (Cleartext Protocol Transmission):**
   - Berdasarkan NIST SP 800-115 (*Section 5.1: Network Discovery & Protocol Inspection*), protokol tanpa enkripsi transport (seperti HTTP pada port 80, Telnet, FTP, TFTP) mentransmisikan seluruh data payload, header otentikasi, dan dokumen respons dalam bentuk plaintext tanpa perlindungan *confidentiality* maupun *integrity*.
   - Kerentanan ini terdaftar pada **CWE-319** (*Cleartext Transmission of Sensitive Information*). Siapa pun yang berada pada posisi *man-in-the-middle* (MITM) atau memiliki akses tap jaringan (network mirror/SPAN port) dapat menyadap seluruh percakapan.

2. **Obfuskasi Sederhana Menggunakan Rotasi Alfabetik (Caesar Cipher / ROT13):**
   - Respons server HTTP dalam tangkapan jaringan membawa body HTML yang diobfuskasi menggunakan sandi substitusi monoalfabetik ROT13:
     $$\text{Ciphertext: } \texttt{Gur synt vf npnqrzl\{c33xno00\_1\_f33\_h\_qrnqorrs\}}$$
   - Sesuai prinsip kriptanalisis dasar:
     - $G \xrightarrow{+13} T, u \xrightarrow{+13} h, r \xrightarrow{+13} e \implies \text{"The"}$
     - $s \xrightarrow{+13} f, y \xrightarrow{+13} l, n \xrightarrow{+13} a, t \xrightarrow{+13} g \implies \text{"flag"}$
     - $v \xrightarrow{+13} i, f \xrightarrow{+13} s \implies \text{"is"}$
     - $n \xrightarrow{+13} a, p \xrightarrow{+13} c, n \xrightarrow{+13} a, q \xrightarrow{+13} d, r \xrightarrow{+13} e, z \xrightarrow{+13} m, l \xrightarrow{+13} y \implies \text{"academy"}$
   - Angka dan simbol garis bawah (`_`, `0`, `1`, `3`) tetap tidak berubah pada translasi ROT13:
     - `c33xno00` $\xrightarrow{\text{ROT13}}$ `p33kab00`
     - `1_f33_h` $\xrightarrow{\text{ROT13}}$ `1_s33_u`
     - `qrnqorrs` $\xrightarrow{\text{ROT13}}$ `deadbeef`

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak PCAPNG:**
   ```bash
   wget https://challenge-files.cylabacademy.net/library/bcc244e5738c2a9af3a7fd84a79e1bf8436dc32716855581a60e27e526133fd7/shark1.pcapng
   ```

2. **Inspeksi String / Rekonstruksi TCP Stream:**
   Menggunakan tcpdump atau skrip python untuk mengekstraksi percakapan HTTP:
   ```bash
   python3 -c '
   with open("shark1.pcapng", "rb") as f:
       data = f.read()
   import re, codecs
   matches = re.findall(rb"npnqrzl\{[^\}]+\}", data)
   for m in set(matches):
       raw = m.decode("latin1")
       print("Raw ROT13:", raw)
       print("Decoded:", codecs.decode(raw, "rot_13"))
   '
   ```
   Output:
   - Raw ROT13: `npnqrzl{c33xno00_1_f33_h_qrnqorrs}`
   - Decoded: `academy{p33kab00_1_s33_u_deadbeef}`

3. **Verifikasi Konteks Aliran Paket HTTP:**
   Header HTTP yang membungkus payload:
   ```http
   HTTP/1.1 200 OK
   Date: Fri, 07 Aug 2020 00:45:02 GMT
   Content-Type: text/html
   Content-Length: 47

   Gur synt vf npnqrzl{c33xno00_1_f33_h_qrnqorrs}
   ```

---

## Flag & Verifikasi

- **Flag:** `academy{p33kab00_1_s33_u_deadbeef}`
- **Verifikasi API CyLab:**
  Submisi HTTP POST langsung ke `/api/submissions/`:
  ```json
  {"challenge": 115, "flag": "academy{p33kab00_1_s33_u_deadbeef}"}
  ```
  Status respons: `HTTP 201 Created` dengan `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Penerapan TLS / HTTPS Menyeluruh (Enforce Transport Encryption):**
   - Nonaktifkan transmisi dokumen sensitif melalui protokol HTTP teks polos (cleartext).
   - Terapkan HTTPS (TLS 1.3) pada web server (Nginx/Apache) dengan sertifikat digital yang valid.
   - Konfigurasikan header `Strict-Transport-Security` (HSTS):
     ```nginx
     add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
     ```
2. **Obfuskasi Bukanlah Enkripsi:**
   - Obfuskasi monoalfabetik seperti ROT13 sama sekali tidak memiliki parameter kunci rahasia (*cryptographic key*). Sesuai NIST SP 800-115, data sensitif harus dilindungi algoritma kriptografi modern yang telah diaudit (seperti AES-GCM atau ChaCha20-Poly1305).
