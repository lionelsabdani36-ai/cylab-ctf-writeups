# 714 - Rogue Tower (Forensics, picoCTF 2026, Medium)

## Challenge Metadata
- ID: 714 | Event: picoCTF 2026 | Author: LT 'syreal' Jones
- Category: Forensics | Difficulty: Medium (2)
- Flag: `academy{r0gu3_c3ll_t0w3r_931ea9c0}`

## Problem Statement & Scope
Tantangan mendistribusikan file tangkapan lalu lintas jaringan `rogue_tower.pcap`. Dalam skenario telekomunikasi seluler, sebuah stasiun pangkalan (*cell tower*) palsu/tak berizin terdeteksi di lingkungan jaringan. Analis diminta menyelidiki lalu lintas paket untuk:
1. Mengidentifikasi tower seluler palsu (*rogue base station* / IMSI Catcher).
2. Menemukan perangkat seluler korban yang terhubung ke tower tersebut.
3. Merekonstruksi data yang dieksfiltrasi dan mendekripsi token flag.

## Teori & Akar Kerentanan (Root Cause)
1. **Rogue Base Stations & IMSI Catcher Architecture (3GPP Security Flaws):**
   Pada arsitektur jaringan seluler warisan (GSM/2G/3G dan mode fallback LTE), stasiun pangkalan (eNodeB / BTS) tidak mewajibkan autentikasi timbal balik (*mutual authentication*) yang kuat sebelum perangkat seluler mentransmisikan identitas uniknya. Penyerang dapat menyiarkan sinyal jaringan uji coba (*unauthorized test network broadcast*) dengan parameter PLMN (Public Land Mobile Network) dan CELLID palsu untuk memancing perangkat seluler terdekat beralih ke tower penyerang (serangan *Man-in-the-Middle / IMSI Catching*).
2. **Kelemahan Penurunan Kunci Kriptografi Statis (CWE-321 / CWE-327):**
   Proses eksfiltrasi mengenkripsi muatan menggunakan algoritma XOR simetris berulang dengan kunci yang diturunkan langsung dari akhiran pengenal pelanggan tetap (IMSI). Nilai IMSI (15 digit angka) bersifat statis dan mudah disadap di udara (*cleartext broadcast*), sehingga kunci XOR 8-bita yang diturunkan (`IMSI[-8:]`) dapat direkonstruksi sepenuhnya tanpa memerlukan materi kriptografis rahasia.
3. **Chunked Covert Exfiltration over HTTP (MITRE ATT&CK T1048):**
   Penyerang memecah muatan biner Base64 ke dalam beberapa permintaan HTTP `POST /upload` berukuran kecil (9 bita per transaksi) pada port yang berbeda untuk menghindari deteksi berbasis ambang batas volume (*traffic threshold alerting*).

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis arsitektur paket `rogue_tower.pcap`:
   - Berkas menggunakan tautan data `DLT_RAW` / `DLT_IPV4` (linktype 228 / `0xE4`), di mana bita langsung merepresentasikan paket IPv4 tanpa header Ethernet.
2. Identifikasi Rogue Tower (Broadcast UDP Port 55000):
   - Paket ke-13 menyiarkan pesan:
     `UNAUTHORIZED-TEST-NETWORK PLMN=00101 CELLID=91729`
   - Teridentifikasi `CELLID = 91729` sebagai stasiun pangkalan palsu.
3. Identifikasi perangkat korban:
   - Pada paket ke-15, perangkat dengan alamat IP `10.100.198.251` mengirimkan permintaan pendaftaran:
     ```http
     GET /api/register HTTP/1.1
     Host: network.carrier.com
     User-Agent: MobileDevice/1.0 (IMSI:310410709993882; CELL:91729)
     ```
   - IMSI korban teridentifikasi: `310410709993882`.
4. Rekonstruksi muatan eksfiltrasi HTTP POST:
   - Paket ke-16 hingga 21 mentransmisikan pecahan bita Base64 ke `198.51.100.117`:
     - Pkt 16: `UVpYXVZVQ`
     - Pkt 17: `UlCCV5MAG`
     - Pkt 18: `dbAVxVZk0`
     - Pkt 19: `DTwtAbwAK`
     - Pkt 20: `CFZZAVEAR`
     - Pkt 21: `A==`
   - Gabungan seluruh fragmen: `UVpYXVZVQUlCCV5MAGdbAVxVZk0DTwtAbwAKCFZZAVEARA==` (48 karakter Base64).
5. Dekripsi XOR berulang:
   - Dekode Base64 menghasilkan 34 bita *ciphertext*.
   - Turunkan kunci XOR dari 8 digit terakhir IMSI korban: `key = "310410709993882"[-8:] = "09993882"`.
   - Lakukan operasi XOR: `plaintext = bytes(c ^ k for c, k in zip(ciphertext, itertools.cycle(key)))`.
   - Diperoleh string: `academy{r0gu3_c3ll_t0w3r_931ea9c0}`.
6. Verifikasi via API CyLab:
   `POST /api/submissions/` dengan payload `{"challenge": 714, "flag": "academy{r0gu3_c3ll_t0w3r_931ea9c0}"}` mengembalikan respons `{"correct": true, "historical": false}`.

## Flag & Verifikasi
- `academy{r0gu3_c3ll_t0w3r_931ea9c0}` (Status: Verified `correct: true`, `historical: false`).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Mitigasi Rogue Base Station pada Standar 5G SA:** Standar 5G Standalone (3GPP TS 33.501) mengimplementasikan SUPI (Subscription Permanent Identifier) yang dienkripsi menggunakan kunci publik jaringan rumah menjadi SUCI (Subscription Concealed Identifier) sebelum dipancarkan di udara, menggugurkan eksploitasi IMSI Catcher.
- **Deteksi Anomali Jaringan Seluler:** Administrator infrastruktur dan SOC harus memantau broadcast seluler tak terotorisasi (PLMN uji coba `00101` atau daya pancar abnormal) serta menerapkan inspeksi terhadap User-Agent yang memaparkan pengenal statis perangkat keras.
