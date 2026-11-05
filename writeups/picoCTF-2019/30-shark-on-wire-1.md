# Writeup: shark on wire 1 (Challenge ID: 30)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Network PCAP Packet Dissection & UDP Stream Tracking
- **Difficulty:** Medium (diff=2)
- **Author:** Danny
- **Event:** picoCTF 2019
- **Points:** 150
- **Flag:** `academy{StaT31355_636f6e6e}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan analisis forensik lalu lintas jaringan (*network packet capture analysis*) menggunakan perkakas seperti Wireshark atau Tshark:
> *"We found this packet capture. Recover the flag."*
> Artefak: `shark-on-wire-1-capture.pcap`

Peserta diberikan berkas tangkapan paket berformat PCAP (*Packet Capture*) bernama `shark-on-wire-1-capture.pcap` berukuran ~144 KB yang merekam aktivitas jaringan lokal. Di dalam tangkapan terdapat campuran beragam protokol layer aplikasi dan transport (mDNS, SSDP, LLMNR, TCP, dan UDP). Peserta diarahkan untuk menganalisis rekonstruksi aliran data (*packet stream reassembly*) guna menemukan flag yang disalurkan melalui transmisi jaringan tanpa proteksi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Format Berkas PCAP & Lapisan Protokol Jaringan (RFC 791 / RFC 768):**
   - Berkas Libpcap memiliki struktur biner teratur: Global Header (24 byte) diikuti oleh urutan record paket dengan Record Header (16 byte: timestamp dan panjang frame) serta payload link-layer (Ethernet II).
   - Protokol UDP (*User Datagram Protocol*, RFC 768) adalah protokol transport *connectionless* dan *stateless*. Berbeda dengan TCP yang menggunakan *three-way handshake*, *sequence numbers*, dan *acknowledgment flags*, datagram UDP dikirimkan secara independen tanpa mekanisme kontrol status sesi bawaan (*stateless communication*).

2. **Konsep Stream Following & Isolasi Percakapan (*Conversation Tracking*):**
   - Dalam penganalisis protokol seperti Wireshark, fitur *Follow UDP Stream* mengelompokkan paket-paket yang memiliki relasi 4-tuple identik:
     $$\text{Flow} = (\text{IP}_{\text{src}}, \text{Port}_{\text{src}}, \text{IP}_{\text{dst}}, \text{Port}_{\text{dst}})$$
   - Dalam berkas pcap ini, penyerang/pengirim mendistribusikan beberapa stream UDP buatan (*synthetic traffic*) antar alamat host internal `10.0.0.0/24`:
     - Aliran menuju `10.0.0.13:8888` membawa flag palsu (*decoy/honeypot artifact*): `academy{N0t_a_fLag}`.
     - Aliran menuju `10.0.0.12:8888` (UDP stream 6) membawa flag resmi yang sah: `academy{StaT31355_636f6e6e}`.
   - Tanpa pemilahan aliran percakapan yang teliti, analis forensik dapat terjebak pada umpan flag palsu.

3. **Transmisi Data Sensitif Tanpa Enkripsi Sesuai Standar NIST SP 800-115:**
   - NIST SP 800-115 (Section 5.1: *Network Discovery and Vulnerability Identification*) mengidentifikasi kerentanan transmisi data sensitif dalam bentuk teks jelas (*cleartext transmission*).
   - Masalah ini diklasifikasikan sebagai CWE-319 (*Cleartext Transmission of Sensitive Information*). Kredensial dan data sensitif disalurkan melalui protokol transport tanpa enkripsi TLS/DTLS, memungkinkan pihak mana pun yang berada pada jalur transit (misalnya melalui sniffing, mirror port, atau ARP spoofing) untuk merekonstruksi isi pesan secara utuh.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak Berkas:**
   Unduh berkas tangkapan jaringan dari repositori aset resmi:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/e64f2c2aaf9bf531af7be1787c1407c47a4cc7b57f251d5108a1151e9721a2d6/shark-on-wire-1-capture.pcap
   ```

2. **Pemeriksaan Statistik Paket Menggunakan `capinfos` & `tshark`:**
   Periksa ringkasan berkas tangkapan:
   ```bash
   capinfos shark-on-wire-1-capture.pcap
   # Number of packets: 1,000+
   # File encapsulation: Ethernet
   ```
   Lakukan enumerasi aliran UDP menggunakan `tshark`:
   ```bash
   tshark -r shark-on-wire-1-capture.pcap -Y "udp" -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport | sort -u
   ```

3. **Penyaringan Aliran Data & Penelusuran Stream UDP:**
   Lakukan ekstraksi muatan data pada port tujuan 8888 yang dicurigai:
   ```bash
   tshark -r shark-on-wire-1-capture.pcap -Y "udp.port == 8888" -T fields -e ip.dst -e data.text
   ```
   Keluaran:
   ```text
   10.0.0.12   academy{StaT31355_636f6e6e}
   10.0.0.13   academy{N0t_a_fLag}
   ```
   Terdapat dua alamat tujuan pada subnet lokal:
   - Host `10.0.0.13` menerima pesan umpan (*decoy*): `academy{N0t_a_fLag}`.
   - Host `10.0.0.12` menerima token autentikasi yang sah: `academy{StaT31355_636f6e6e}`.

4. **Ekstraksi Otomatis Melalui Skrip Python Solver:**
   Skrip `scripts/solve_30_shark_on_wire_1.py` mem-parsing biner PCAP secara mandiri, memetakan setiap datagram UDP ke dalam tabel hash stream, mengabaikan flag umpan, dan mencetak token flag asli:
   ```bash
   python3 scripts/solve_30_shark_on_wire_1.py
   ```
   Keluaran:
   ```text
   [+] Recovered Flag: academy{StaT31355_636f6e6e}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{StaT31355_636f6e6e}`
- **Bukti Validasi REST API CyLab:** Endpoint `POST /api/submissions/` merespons dengan HTTP Status 201 Created:
  ```json
  {
    "user": 1072359,
    "challenge": 30,
    "flag": "academy{StaT31355_636f6e6e}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Penerapan pada Modul Network Forensics & Packet Analysis LKS:**
   - Dalam kompetisi LKS Cyber Security, peserta kerap dihadapkan pada berkas tangkapan jaringan bervolume besar yang sarat lalu lintas sampah (*noise traffic*) seperti beacon UPnP, DHCP discover, atau SSDP multi-cast.
   - Kunci keberhasilan triage jaringan adalah mengisolasi percakapan titik-ke-titik (*point-to-point flows*), memanfaatkan display filter Wireshark (`udp.stream eq X`, `frame contains "academy"`), serta memvalidasi keaslian artefak terhadap kemungkinan umpan (*honeytokens/decoys*).

2. **Mitigasi Defensif & Hardening (Network Security & Transport Encryption):**
   - **Enkripsi Lapisan Transport (DTLS / IPsec):** Seluruh komunikasi datagram UDP sensitif antar-layanan mikro atau kontrol industri wajib dilindungi dengan DTLS (*Datagram Transport Layer Security*, RFC 6347) atau enkripsi terowongan IPsec/WireGuard guna mencegah penyadapan pasif.
   - **Segmentasi Jaringan & VLAN Hardening:** Terapkan pembatasan isolasi port (Private VLAN) pada switch akses untuk mencegah penyerang pada host yang disusupi melakukan penyadapan lalu lintas lintas-host (*cross-host promiscuous sniffing*).
