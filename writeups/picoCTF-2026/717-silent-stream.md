# Writeup: Silent Stream (Challenge ID: 717)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Network Protocol Traffic Reassembly & Byte Stream Reversal
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{tr4ck_th3_tr4ff1c_4e0b942e}`
- **Flag Komunitas:** `CTF{tr4ck_th3_tr4ff1c_4e0b942e}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 793 (Transmission Control Protocol Specification: Stream Reassembly & Sequence Numbers), ISO/IEC 10918-1 (Digital Compression and Coding of Continuous-tone Still Images - JPEG), & CWE-326 (Inadequate Encryption Strength).

---

## Problem Statement & Scope

Pada modul bimbingan teknis persiapan lomba LKS `Silent Stream`, peserta diuji dalam menghubungkan analisis forensik lalu lintas jaringan (network packet inspection) dengan teknik rekayasa balik (reverse engineering) pada saluran transmisi data terenkripsi ad-hoc:
- Skenario lingkungan: Diberikan dua berkas artefak penyelidikan:
  1. Berkas tangkapan paket jaringan Libpcap: `packets.pcap` (berisi 136 paket transmisi data).
  2. Skrip pengkodean pengirim Python: `encrypt.py`.
- Pernyataan tantangan:
  > *"We recovered a suspicious packet capture file that seems to contain a transferred file. The sender was kind enough to also share the script they used to encode and send it. Can you reconstruct the original file and find the flag?"*
- Sasaran pengujian:
  1. Menganalisis lalu lintas jaringan pada lapisan transport (TCP/IP) untuk mengekstraksi aliran data mentah.
  2. Mengidentifikasi kelemahan pada skema cipher pergeseran bita aditif pengirim ($k = 42$).
  3. Mengurutkan dan merekonstruksi segmen muatan TCP secara sekuensial berdasarkan *Sequence Number* untuk menghindari korupsi data.
  4. Menerapkan inversi transformasi pergeseran modular $\mathbb{Z}_{256}$ untuk memulihkan berkas citra JPEG/JFIF asli.
  5. Melakukan inspeksi visual/OCR terhadap token rahasia dan memvalidasi token resmi pada endpoint REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Analisis Protokol Transport Layer (RFC 793 - TCP Stream Reassembly):**
   Protokol TCP (*Transmission Control Protocol*) beroperasi berdasarkan konsep aliran bita (*byte stream*) berurutan dan andal di atas jaringan paket yang tidak andal (*unreliable packet-switched network*).
   Ketika berkas ditransmisikan, muatan dibagi menjadi segmen-segmen TCP. Setiap segmen memiliki atribut 32-bit *Sequence Number* yang menunjukkan posisi bita pertama dalam aliran data logis.
   Dalam analisis forensik jaringan (Network Forensics), ekstraksi data tidak dapat mengandalkan urutan kedatangan paket (*packet arrival order*) karena adanya *out-of-order delivery*, *retransmission*, atau *jitter*. Segmen muatan wajib diurutkan secara deterministik berdasarkan relasi:
   $$\text{Offset}_i = \text{Seq}_i - \text{Seq}_{\text{initial}}$$
   untuk menyusun kembali bita muatan secara utuh.

2. **Kelemahan Sandi Substitusi Aditif Monoalfabetik (CWE-326):**
   Skrip transmisi pengirim `encrypt.py` menerapkan fungsi pergeseran modular konstan pada setiap bita:
   $$E(b) = (b + k) \pmod{256}$$
   dengan kunci offset $k = 42$.
   Struktur aljabar gelanggang bilangan bulat $\mathbb{Z}_{256}$ mempertahankan invarian relasional antar bita:
   - Tidak ada difusi (*zero diffusion*): perubahan satu bita plaintext tidak mempengaruhi bita ciphertext lainnya.
   - Tidak ada keacakan kunci dinamis (*zero key schedule / PRNG*).
   - Operasi invers bersifat deterministik dan dapat dihitung langsung melalui pengurangan modular:
     $$D(c) = (c - k) \pmod{256} = (c - 42) \pmod{256}$$

3. **Validasi Tanda Tangan Format File (ISO/IEC 10918-1 / JFIF Standard):**
   Format citra standar JFIF (*JPEG File Interchange Format*) memiliki penanda biner baku (*magic bytes*):
   - *Start of Image* (SOI): `0xFF 0xD8`
   - *Application Marker 0* (APP0): `0xFF 0xE0`
   - Panjang segmen APP0: `0x00 0x10`
   - Pengenal format: ASCII `JFIF\0` (`0x4A 0x46 0x49 0x46 0x00`)
   Ketika segmen TCP pertama yang ditangkap memiliki muatan awal `0x29 0x02 0x29 0x0A`, dilakukan perhitungan selisih modular terhadap penanda SOI dan APP0:
   $$(0x29 - 0xFF) \pmod{256} = (-214) \pmod{256} = 42$$
   $$(0x02 - 0xD8) \pmod{256} = (-214) \pmod{256} = 42$$
   Hal ini membuktikan secara matematis tanpa keraguan bahwa kunci pergeseran yang digunakan adalah tepat $k = 42$.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Artefak Lalu Lintas Jaringan `packets.pcap`:**
   Menganalisis berkas PCAP menggunakan pembaca biner Python (`struct.unpack`):
   - Header berkas PCAP: Magic bytes `0xA1B2C3D4` mengonfirmasi format libpcap standar (*little-endian*).
   - Filter paket IPv4 (`EtherType 0x0800`) dengan protokol TCP (`protocol = 6`).
   - Identifikasi lalu lintas data berarah ke port target 9000 (`dport == 9000`).

2. **Ekstraksi dan Pengurutan Segmen Muatan TCP:**
   - Ditemukan 136 paket transmisi data yang membawa muatan TCP.
   - Setiap paket diekstraksi nilai 32-bit `Sequence Number` beserta data biner muatannya.
   - Segmen diurutkan berdasarkan `Sequence Number` menaik:
     ```python
     segments.sort(key=lambda x: x[0])  # Sort by seq number
     raw_stream = bytearray()
     for seq, chunk in segments:
         raw_stream.extend(chunk)
     ```
   - Total ukuran muatan teragregasi yang terkumpul adalah tepat 8.641 bita.

3. **Inversi Cipher Modular $\mathbb{Z}_{256}$:**
   - Menerapkan fungsi invers terhadap seluruh bita aliran data:
     ```python
     recovered = bytearray((b - 42) % 256 for b in raw_stream)
     ```
   - Memverifikasi 4 bita awal berkas hasil rekonstruksi:
     `recovered[:4] == b'\xff\xd8\xff\xe0'`
     Nilai tersebut cocok secara sempurna dengan *magic bytes* citra JPEG/JFIF.

4. **Inspeksi Citra Digital & Pemulihan Flag:**
   - Menyimpan bita hasil rekonstruksi ke dalam berkas `recovered.jpg` (dimensi 800x500 piksel).
   - Analisis visual pada koordinat teks citra mengungkap string token flag resmi LKS:
     `academy{tr4ck_th3_tr4ff1c_4e0b942e}`.

5. **Validasi Submisi ke REST API CyLab Academy:**
   Mengirimkan token ke endpoint `POST /api/submissions/` dengan header `X-CSRFToken`:
   ```bash
   python3 scripts/solve_717_silent_stream.py --submit
   ```
   Server mengembalikan kode status HTTP `201 Created` dengan konfirmasi validasi `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{tr4ck_th3_tr4ff1c_4e0b942e}`
- **Flag Komunitas:** `CTF{tr4ck_th3_tr4ff1c_4e0b942e}`
- **Log Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 717,
    "flag": "academy{tr4ck_th3_tr4ff1c_4e0b942e}",
    "correct": true,
    "historical": false
  }
  ```
  Status respons HTTP: `201 Created` mengonfirmasi token valid dan tercatat secara definitif pada basis data penilaian.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Rekomendasi Remediasi & Hardening (Defensive Perspective):**
   - **Penerapan Transport Layer Security (TLS 1.3 / RFC 8446):** Komunikasi data sensitif melalui jaringan publik atau internal wajib dienkripsi menggunakan protokol standar industri seperti TLS dengan algoritma cipher suite terakreditasi (misalnya `TLS_AES_256_GCM_SHA384` atau `TLS_CHACHA20_POLY1305_SHA256`). Penggunaan cipher ad-hoc berbasis substitusi byte dilarang keras karena tidak memberikan kerahasiaan (*confidentiality*) maupun integritas (*integrity/AEAD*).
   - **Pencegahan Saluran Eksfiltrasi Terselubung (Covert Channel Detection):** Konfigurasikan Network Intrusion Detection/Prevention Systems (NIDS/NIPS seperti Zeek atau Suricata) untuk memantau lalu lintas jaringan keluar (*egress filtering*). Deteksi transmisi biner non-protokoler pada port non-standar (misalnya port 9000) dan aktifkan *deep packet inspection* (DPI) serta inspeksi entropi untuk mengidentifikasi kebocoran data terenkripsi atau tersamar.

2. **Relevansi Modul LKS Cyber Security:**
   - **Network Forensics & Packet Carving:** Peserta LKS Cyber Security dituntut menguasai keterampilan membedah struktur internal paket PCAP (Ethernet, IPv4, TCP headers), menyusun kembali aliran bita TCP secara programatik menggunakan bahasa Python, serta melakukan *file carving* dari artefak jaringan mentah.
   - **Kriptoanalisis Cipher Substitusi Klasik pada Data Modern:** Membekali peserta dengan kemampuan mengenali pola tanda tangan bita (*magic bytes*) pada berkas multimedia untuk membongkar kunci substitusi modular secara instan.
