# Writeup: PcapPoisoning (Challenge ID: 362)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Packet Analysis (RFC 793 / CWE-319)
- **Difficulty:** Medium (diff=2)
- **Event:** picoCTF 2023
- **Points:** 100
- **Author:** LT 'syreal' Jones
- **Flag:** `academy{P64P_4N4L7S1S_SU55355FUL_7a51913b}`

---

## Problem Statement & Scope

Tantangan menyediakan file rekaman tangkapan lalu lintas jaringan (`trace.pcap`). Objektif investigasi adalah mengidentifikasi dan merekonstruksi token bendera yang tersembunyi di dalam aliran paket data tanpa kredensial awal.

---

## Teori & Akar Kerentanan (Root Cause Theory - NIST SP 800-115 § 4.2)

1. **Transmisi Data Sensitif Tanpa Enkripsi (CWE-319 / Cleartext Transmission of Sensitive Information):**
   Transmisi data melalui protokol TCP (RFC 793) tanpa enkripsi lapisan aplikasi (TLS/HTTPS) mengekspos seluruh isi payload paket kepada pengamat jaringan pasif atau analis forensik.
2. **Rekonstruksi Aliran Data Jaringan (Network Protocol Stream Carving):**
   Pada analisis forensik jaringan, artefak plaintext dapat diidentifikasi secara langsung melalui inspeksi paket per frame, rekonstruksi TCP stream, atau ekstraksi string biner berbasis ekspresi reguler.
3. **Struktur Paket #507:**
   Token bendera berada pada payload TCP segmen #507 di kanal komunikasi data, dikirimkan secara langsung tanpa obfuscation, kompresi tambahan, atau kontrol integritas kriptografis.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Unduh Artefak:**
   Unduh berkas `trace.pcap` dari CDN CyLab Academy (`challenge-files.cylabacademy.net/library/...`).
2. **Analisis Paket dan Ekstraksi String:**
   Gunakan utilitas analisis biner seperti `strings`, Wireshark, atau skrip Python:
   ```bash
   strings trace.pcap | grep -E "(academy|picoCTF)\{"
   ```
   Atau menggunakan tshark:
   ```bash
   tshark -r trace.pcap -Y 'tcp contains "academy{"' -T fields -e text
   ```
3. **Ekstraksi Otomatis:**
   Jalankan skrip pemulihan mandiri `scripts/solve_362_pcap_poisoning.py` yang memindai byte stream secara langsung dan mengekstrak token:
   `academy{P64P_4N4L7S1S_SU55355FUL_7a51913b}`.
4. **Verifikasi Token via REST API:**
   Pengiriman permintaan `POST /api/submissions/` dengan payload `{"challenge": 362, "flag": "academy{P64P_4N4L7S1S_SU55355FUL_7a51913b}"}` dan header `X-CSRFToken` menghasilkan respon HTTP 201 Created dengan status `correct: true`.

---

## Flag & Verifikasi

- **Flag:** `academy{P64P_4N4L7S1S_SU55355FUL_7a51913b}`
- **Bukti Validasi:** REST API CyLab `/api/submissions/` mengembalikan respon valid:
  ```json
  {"user": 1072359, "challenge": 362, "flag": "academy{P64P_4N4L7S1S_SU55355FUL_7a51913b}", "correct": true, "historical": false}
  ```
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi mandiri `scripts/solve_362_pcap_poisoning.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115 § 4.4)

1. **Kompetensi LKS Cyber Security:**
   Penguasaan metodologi inspeksi PCAP, pemfilteran Wireshark/tshark (`tcp.payload contains "academy"`), pemahaman struktur frame Ethernet/IP/TCP RFC 793, serta string carving pada artefak pcapng/pcap.
2. **Mitigasi Defensif (Enkripsi End-to-End):**
   Terapkan enkripsi end-to-end berbasis TLS 1.3 pada semua kanal transmisi data sensitif untuk mencegah *eavesdropping* dan *packet sniffing*.
3. **Segmentasi Jaringan dan Audit Lalu Lintas:**
   Terapkan kontrol akses jaringan (VLAN / firewall micro-segmentation) dan sensor Network Intrusion Detection System (NIDS seperti Zeek/Suricata) untuk memantau keberadaan aliran data unencrypted di zona sensitif.
