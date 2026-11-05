# Writeup: Packets Primer (Challenge ID: 286)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Network Traffic Analysis & Packet Dissection
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{p4ck37_5h4rk_7ff5a1b3}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan analisis lalu lintas jaringan (*network forensics*):
> *"Download the packet capture file and use packet analysis software to find the flag."*
> *Hint: Wireshark, if you can install and use it, is probably the most beginner friendly packet analysis software product.*
> Artefak: `network-dump.flag.pcap`

Peserta diberikan berkas tangkapan paket jaringan `network-dump.flag.pcap` sebesar 778 bita. Peserta diminta membedah frame jaringan dan mengidentifikasi komunikasi data sensitif yang ditransmisikan tanpa enkripsi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Berkas PCAP (RFC/Libpcap Standard):**
   - Format Libpcap diawali oleh *Global Header* 24 bita (magic number `0xd4c3b2a1` untuk little-endian) yang mendefinisikan versi format, zona waktu, dan *link-layer header type* (umumnya Ethernet / `LINKTYPE_ETHERNET` = 1).
   - Setiap paket direkam dalam struktur *Packet Header* 16 bita (timestamp detik, microdetik, panjang tangkapan `incl_len`, dan panjang asli pada kabel `orig_len`), diikuti oleh bita muatan paket (*packet data*).

2. **Transmisi Teks Terbuka (*Cleartext Transmission*, CWE-319):**
   - Protokol lapisan transport (TCP) memfasilitasi aliran komunikasi data dua arah yang andal. Namun, tanpa lapisan keamanan kriptografis seperti TLS/SSL (RFC 8446), seluruh data muatan aplikasi (*application layer payload*) ditransmisikan dalam format teks polos (*plaintext*).
   - Penyerang yang memiliki akses ke media transmisi (misalnya melalui ARP poisoning, mirror port, atau sniffing pada jaringan nirkabel tak terenkripsi) dapat merekonstruksi seluruh isi pesan tanpa memerlukan kunci dekripsi.
   - Pada berkas ini, pengirim mengaburkan pembacaan otomatis sederhana dengan menyisipkan spasi di antara setiap karakter flag (`a c a d e m y { ... }`), namun struktur TCP stream tetap sepenuhnya terbaca.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak Berkas:**
   Unduh tangkapan PCAP dari repositori resmi:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/bf6ce90b17a773e3381a0b32b3bc624a0c8818e09346f5cee59e9fc66088934a/network-dump.flag.pcap
   ```

2. **Inspeksi Frame & Aliran TCP via Wireshark / TShark:**
   - Buka berkas dengan Wireshark atau gunakan `tshark` di terminal:
     ```bash
     tshark -r network-dump.flag.pcap -Y "tcp"
     ```
   - Terlihat 4 paket TCP:
     - Paket 1: `10.0.2.15:48750 -> 10.0.2.4:9000 [SYN]`
     - Paket 2: `10.0.2.4:9000 -> 10.0.2.15:48750 [SYN, ACK]`
     - Paket 3: `10.0.2.15:48750 -> 10.0.2.4:9000 [ACK]`
     - Paket 4: `10.0.2.15:48750 -> 10.0.2.4:9000 [PSH, ACK]` dengan muatan data 60 bita.

3. **Follow TCP Stream:**
   Gunakan fitur *Follow TCP Stream* (stream 0) atau inspeksi payload data pada paket 4:
   ```bash
   tshark -r network-dump.flag.pcap -z "follow,tcp,ascii,0"
   ```
   Keluaran muatan aliran data:
   ```text
   a c a d e m y { p 4 c k 3 7 _ 5 h 4 r k _ 7 f f 5 a 1 b 3 }
   ```

4. **Normalisasi Token Flag:**
   Hilangkan karakter spasi pengabur untuk mendapatkan string token flag yang valid:
   ```python
   raw = "a c a d e m y { p 4 c k 3 7 _ 5 h 4 r k _ 7 f f 5 a 1 b 3 }"
   flag = "".join(raw.split())
   print(flag)
   # Hasil: academy{p4ck37_5h4rk_7ff5a1b3}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{p4ck37_5h4rk_7ff5a1b3}`
- **Verifikasi API Platform:** Validasi token melalui endpoint `POST /api/submissions/` menghasilkan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 286, "flag": "academy{p4ck37_5h4rk_7ff5a1b3}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Network Packet Analysis menggunakan Wireshark/tshark dan NetworkMiner merupakan salah satu modul pengujian teknis vital dalam LKS Cyber Security. Peserta harus mahir membaca three-way handshake TCP (SYN, SYN-ACK, ACK), menganalisis aliran data muatan (TCP/UDP streams), dan mengekstraksi objek/berkas yang dikirim melalui jaringan.
- **Mitigasi Defensif (Pencegahan Sadap Jaringan & Perlindungan Transmisi Data):**
  1. *Penerapan Enkripsi Transport End-to-End (TLS/IPSec):* Seluruh komunikasi internal dan eksternal aplikasi yang mentransmisikan data kredensial atau informasi sensitif wajib dienkripsi menggunakan protokol aman modern (TLS 1.3 / mTLS / VPN IPSec), sehingga data yang terekam pada tap jaringan atau perangkat intermediat tidak dapat didekomposisi menjadi teks polos.
  2. *Segmentasi Jaringan & Port Security:* Terapkan 802.1X Network Access Control, Dynamic ARP Inspection (DAI), dan DHCP Snooping pada switch jaringan lokal guna mencegah serangan Man-in-the-Middle (MitM) yang memfasilitasi packet sniffing liar.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_286_packets_primer.py`.
