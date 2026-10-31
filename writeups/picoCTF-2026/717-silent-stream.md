# 717 - Silent Stream (Reverse Engineering, picoCTF 2026, Medium)

## Challenge Metadata
- ID: 717 | Event: picoCTF 2026 | Author: LT 'syreal' Jones
- Category: Reverse Engineering | Difficulty: Medium (2)
- Flag: `academy{tr4ck_th3_tr4ff1c_4e0b942e}`

## Problem Statement & Scope
Tantangan mendistribusikan file tangkapan paket jaringan `packets.pcap` beserta skrip penyandi pengirim `encrypt.py`. Skenario menggambarkan transmisi file mencurigakan melalui jaringan yang telah disandikan sebelum dikirimkan. Analis diminta merekonstruksi file asli dari aliran TCP dan mengungkap flag yang disembunyikan.

## Teori & Akar Kerentanan (Root Cause)
1. **Analisis Protokol Transport Layer (RFC 793 - TCP Stream Reassembly):**
   Protokol TCP menyediakan layanan aliran bita (byte stream) berurut dan andal. Paket-paket data dipecah ke dalam segmen dengan nomor urut (`sequence number`). Dalam rekonstruksi artefak jaringan, potongan muatan (`payload`) dari segmen TCP harus diurutkan berdasarkan `Sequence Number` untuk menghindari korupsi data akibat keterlambatan atau out-of-order packet delivery.
2. **Kriptografi Substitusi Sederhana (Caesar Byte Shift / Modulo 256):**
   Skrip `encrypt.py` menerapkan fungsi pergeseran modular aditif pada setiap bita:
   $$E(b) = (b + k) \pmod{256}$$
   dengan nilai default kunci $k = 42$. Karena gelanggang bita $\mathbb{Z}_{256}$ bersifat siklik terbalik di bawah operasi pengurangan modular:
   $$D(c) = (c - k) \pmod{256}$$
   sandi ini tidak memiliki sifat difusi (*zero diffusion*) dan mudah dipecahkan menggunakan identifikasi tanda tangan bita berkas (*magic bytes signature*).
3. **Validasi Tanda Tangan Format File (JFIF / JPEG):**
   Format berkas citra JPEG (ISO/IEC 10918-1) selalu diawali dengan *Start of Image* (SOI) marker `0xFF 0xD8` diikuti oleh penanda aplikasi JFIF `0xFF 0xE0 0x00 0x10 'JFIF'`. Menghitung selisih antara 4 bita awal muatan TCP (`0x29 0x02 0x29 0x0A`) dan tanda tangan JPEG membuktikan secara eksak bahwa nilai $k = 42$.

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis kode sumber pengirim `encrypt.py`:
   ```python
   def encode_byte(b, key):
       return (b + key) % 256
   ```
2. Parse `packets.pcap` untuk mengekstrak segmen TCP:
   - Filter paket IPv4 (`EtherType 0x0800`) dan protokol TCP (`proto = 6`) tujuan port 9000.
   - Ambil muatan data TCP dan pasangkan dengan `seq number`.
   - Urutkan segmen berdasarkan urutan nomor urut (`seq`) untuk memperoleh 8.641 bita muatan utuh.
3. Dekripsi muatan bita terurut:
   - Hitung invers transformasi: `recovered = bytes((b - 42) % 256 for b in raw_payload)`.
   - Verifikasi 4 bita pembuka: `recovered[:4] == b'\xff\xd8\xff\xe0'`, mengonfirmasi rekoveri citra JPEG berukuran 800x500 piksel.
4. Analisis visual dan ekstraksi token flag:
   - Citra JPEG menampilkan teks token flag yang dirender pada koordinat $y \in [201, 211]$ dan $x \in [300, 478]$.
   - Melakukan cropping, upscaling 6x dengan interpolasi Lanczos, dan binarisasi menghasilkan token terverifikasi:
     `academy{tr4ck_th3_tr4ff1c_4e0b942e}`.
5. Verifikasi via API CyLab:
   `POST /api/submissions/` dengan payload `{"challenge": 717, "flag": "academy{tr4ck_th3_tr4ff1c_4e0b942e}"}` menghasilkan respons `{"correct": true, "historical": false}`.

## Flag & Verifikasi
- `academy{tr4ck_th3_tr4ff1c_4e0b942e}` (Status: Verified `correct: true`, `historical: false`).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Eksfiltrasi Saluran Terselubung (Covert Channel & Data Exfiltration):** Dalam skenario kompetisi LKS modul Network Forensics & Defensive Monitoring, serangan sering memanfaatkan protokol umum (TCP raw sockets, DNS tunneling, ICMP payload) dengan enkripsi ad-hoc untuk menyamarkan pencurian data sensitif.
- **DLP & Deep Packet Inspection (DPI):** Sistem pertahanan jaringan (NIDS/IPS seperti Zeek dan Suricata) harus dilengkapi dengan deteksi entropi dan analisis anomali protokol untuk mengidentifikasi lalu lintas bita berulang atau transmisi biner tak terotorisasi pada port non-standar (port 9000).
