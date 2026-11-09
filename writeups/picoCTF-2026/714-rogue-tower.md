# Writeup: Rogue Tower (Challenge ID: 714)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Rogue Cellular Base Station (Fake BTS / IMSI Catcher) & Repeating-Key XOR Exfiltration
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{r0gu3_c3ll_t0w3r_931ea9c0}`
- **Flag Komunitas:** `CTF{r0gu3_c3ll_t0w3r_931ea9c0}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), 3GPP TS 33.501 (Security Architecture and Procedures for 5G System), 3GPP TS 33.102 (3G Security Architecture), RFC 791 (IPv4 Protocol), CWE-321 (Use of Hard-coded Cryptographic Key), CWE-327 (Use of Broken Cryptographic Algorithm - Repeating XOR), & MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol).

---

## Problem Statement & Scope

Pada modul bimbingan teknis persiapan lomba LKS `Rogue Tower`, peserta diuji dalam menganalisis berkas tangkapan paket jaringan nirkabel telekomunikasi seluler serta melacak jejak eksfiltrasi data intelijen yang dilakukan oleh stasiun pangkalan seluler palsu (*rogue base station* / IMSI Catcher):
- Skenario lingkungan: Diberikan satu berkas artefak PCAP: `rogue_tower.pcap` yang berisi lalu lintas raw IPv4 (linktype 228 / `DLT_RAW`).
- Pernyataan tantangan:
  > *"A suspicious cell tower has been detected in the network. Analyze the captured network traffic to identify the rogue tower, find the compromised device, and recover the exfiltrated flag."*
- Sasaran pengujian:
  1. Menemukan siaran anomali stasiun pangkalan tak berizin (*unauthorized test network broadcast*) pada port UDP 55000.
  2. Mengidentifikasi pengenal seluler unik target (*CELLID*) dan International Mobile Subscriber Identity (*IMSI*) dari perangkat pengguna yang tertipu (*lured mobile subscriber*).
  3. Merekonstruksi aliran transaksi HTTP POST terfragmentasi (*chunked exfiltration*) yang dikirimkan ke server penampung eksternal (`198.51.100.117:443`).
  4. Menganalisis skema penurunan kunci kriptografi berbasis sufiks IMSI 8-digit dan membalikkan enkripsi XOR berulang.
  5. Memvalidasi token plaintext resmi pada endpoint REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Rogue Base Stations & IMSI Catcher Architecture (3GPP Security Weakness):**
   Pada arsitektur telekomunikasi seluler generasi lawas (GSM/2G/3G serta fase awal negosiasi sambungan LTE RRC), prosedur pemilihan sel (*cell selection/reselection*) memprioritaskan stasiun pemancar dengan kuat sinyal (RSSI / RSRP) tertinggi tanpa mewajibkan autentikasi timbal balik (*mutual authentication*) sebelum identitas perangkat diserahkan.
   - Penyerang mendirikan Base Transceiver Station (BTS) atau eNodeB palsu yang menyiarkan parameter Public Land Mobile Network (PLMN) uji coba (`00101`) dengan pengenal unik (`CELLID=91729`).
   - Perangkat seluler korban yang berada di dekat menara palsu secara otomatis melakukan *handover* dan mengirimkan pesan registrasi awal (`GET /api/register`) yang memuat nomor identitas permanen pelanggan (IMSI).
   - Fenomena ini dikenal sebagai serangan *IMSI Catching / StingRay attack*.

2. **Kelemahan Penurunan Kunci Kriptografi Berbasis Sufiks IMSI (CWE-321 / CWE-327):**
   Aplikasi atau implan penyerang pada perangkat terkompromi mengenkripsi berkas rahasia sebelum dieksfiltrasi menggunakan cipher XOR simetris berulang (*repeating-key XOR*):
   $$c_i = m_i \oplus k_{i \pmod L}$$
   Di mana kunci $k$ diturunkan secara deterministik dari 8 digit terakhir IMSI korban:
   $$k = \text{IMSI}[-8:] = \text{"09993882"}$$
   Karena nomor IMSI dipancarkan secara terbuka di saluran udara (*cleartext broadcast*) selama registrasi seluler, kunci XOR tersebut tidak memiliki status kerahasiaan (*zero cryptographic secrecy*), memungkinkan penyerang maupun pengamat lalu lintas (*eavesdropper*) mendekripsi seluruh data secara deterministik.

3. **Eksfiltrasi Terfragmentasi Melalui Protokol Alternatif (MITRE ATT&CK T1048):**
   Untuk mengelabui sensor Network Intrusion Detection System (NIDS) dan inspeksi berbasis ambang batas volume (*payload size thresholding*), data biner dienkode ke format Base64 dan dipecah ke dalam beberapa permintaan HTTP `POST /upload` kecil (masing-masing 9 karakter):
   - Transmisi dilakukan secara bertahap ke IP eksternal `198.51.100.117` pada port 443.
   - Rekonstruksi membutuhkan penyambungan (*reassembly*) urutan fragmen Base64 sebelum proses dekripsi biner dilakukan.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Header & Tipe Tautan PCAP:**
   Berkas `rogue_tower.pcap` menggunakan tautan data mentah `DLT_RAW` / `DLT_IPV4` (linktype `0xE4` / 228), tanpa enkapsulasi frame Ethernet IEEE 802.3. Setiap frame paket langsung diawali dengan header IPv4 20-byte.

2. **Identifikasi Stasiun Pangkalan Palsu (UDP Broadcast Port 55000):**
   Menganalisis paket siaran UDP pada port 55000:
   - Paket ke-13 memancarkan string diagnostik:
     ```text
     UNAUTHORIZED-TEST-NETWORK PLMN=00101 CELLID=91729
     ```
   - Parameter terkonfirmasi: Stasiun pangkalan tak berizin menggunakan `CELLID = 91729`.

3. **Identifikasi Perangkat Korban yang Terpancing (HTTP Registration):**
   Mencari lalu lintas TCP yang menuju atau merujuk ke `CELL:91729`:
   - Pada paket registrasi HTTP:
     ```http
     GET /api/register HTTP/1.1
     Host: network.carrier.com
     User-Agent: MobileDevice/1.0 (IMSI:310410709993882; CELL:91729)
     ```
   - Parameter korban:
     - Alamat IP: `10.100.198.251`
     - Nomor IMSI: `310410709993882`
     - Kunci XOR (8 digit terakhir): `"310410709993882"[-8:]` = `"09993882"` (ASCII bytes: `[0x30, 0x39, 0x39, 0x39, 0x33, 0x38, 0x38, 0x32]`).

4. **Ekstraksi & Rekonstruksi Fragmen Eksfiltrasi HTTP POST:**
   Mengisolasi aliran TCP sesi eksfiltrasi ke IP `198.51.100.117:443`:
   - Enam paket HTTP `POST /upload` mentransmisikan bodi Base64 berikut:
     1. Pkt 16: `UVpYXVZVQ`
     2. Pkt 17: `UlCCV5MAG`
     3. Pkt 18: `dbAVxVZk0`
     4. Pkt 19: `DTwtAbwAK`
     5. Pkt 20: `CFZZAVEAR`
     6. Pkt 21: `A==`
   - Menggabungkan seluruh fragmen secara berurutan:
     ```text
     UVpYXVZVQUlCCV5MAGdbAVxVZk0DTwtAbwAKCFZZAVEARA==
     ```
   - Total panjang string Base64: 48 karakter.
   - Dekode Base64 menghasilkan 34 bita *ciphertext* biner:
     `51 5a 58 5d 56 55 41 49 42 09 5e 4c 01 a7 5b 01 5c 55 66 4d 03 4f 0b 40 6f 00 0a 08 56 59 01 51 01 10`

5. **Dekripsi Kriptografis XOR Berulang:**
   Menerapkan operasi XOR antara tiap bita ciphertext dengan bita kunci `"09993882"` secara siklik:
   ```python
   import base64, itertools

   b64_data = "UVpYXVZVQUlCCV5MAGdbAVxVZk0DTwtAbwAKCFZZAVEARA=="
   ciphertext = base64.b64decode(b64_data)
   key = b"09993882"

   plaintext = bytes(c ^ k for c, k in zip(ciphertext, itertools.cycle(key)))
   print(plaintext.decode())
   # Output: academy{r0gu3_c3ll_t0w3r_931ea9c0}
   ```

6. **Validasi Submisi ke REST API CyLab Academy:**
   Mengirimkan token verifikasi ke endpoint `POST /api/submissions/` dengan payload JSON `{"challenge": 714, "flag": "academy{r0gu3_c3ll_t0w3r_931ea9c0}"}`:
   ```bash
   python3 scripts/solve_714_rogue_tower.py --submit
   ```
   Server mengembalikan kode status HTTP `201 Created` dengan konfirmasi validasi `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{r0gu3_c3ll_t0w3r_931ea9c0}`
- **Flag Komunitas:** `CTF{r0gu3_c3ll_t0w3r_931ea9c0}`
- **Log Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 714,
    "flag": "academy{r0gu3_c3ll_t0w3r_931ea9c0}",
    "correct": true,
    "historical": false
  }
  ```
  Status respons HTTP: `201 Created` mengonfirmasi token valid dan tercatat secara definitif pada basis data penilaian.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Rekomendasi Remediasi & Hardening (Defensive Perspective):**
   - **Penerapan Autentikasi SUPI/SUCI pada 5G Standalone (3GPP TS 33.501):** Pada jaringan 5G SA modern, identitas permanen pelanggan (SUPI) tidak pernah dipancarkan secara terbuka di udara. Perangkat mengenkripsi SUPI menggunakan kunci publik operator (*Home Network Public Key*) menjadi SUCI (*Subscription Concealed Identifier*) dengan skema ECIES sebelum dikirimkan ke menara seluler, memitigasi serangan IMSI Catcher secara total.
   - **Pemantauan Siaran Seluler Anomali (Cellular Threat Defense / CTD):** Infrastruktur pertahanan telekomunikasi dan SOC wajib menempatkan sensor pemantau RF (*RF sniffers / cellular IDS*) untuk mendeteksi stasiun pangkalan yang memancarkan PLMN tak dikenal (`00101`), parameter penyiaran abnormal, atau lonjakan daya transmisi (*RF spoofing*).
   - **Pencegahan Kebocoran Header Perangkat (Privacy by Design):** Aplikasi seluler dilarang keras menyematkan pengenal perangkat statis perangkat keras (IMSI, IMEI, MEID) ke dalam header HTTP `User-Agent`. Setiap komunikasi jaringan wajib dibungkus dalam TLS 1.3 dengan *Certificate Pinning*.

2. **Relevansi Modul LKS Cyber Security:**
   - **Network Forensics & Packet Dissection:** Peserta LKS Cyber Security dituntut menguasai inspeksi berkas tangkapan PCAP raw tanpa bantuan antarmuka grafis (Wireshark GUI), membedah struktur header layer IP dan TCP, serta merekonstruksi muatan stream data terfragmentasi.
   - **Korelasi Bukti Digital:** Kemampuan menghubungkan anomali siaran kontrol jaringan (UDP broadcast) dengan aktivitas lapisan aplikasi korban (HTTP register) untuk mengekstrak artefak kunci dekripsi.
