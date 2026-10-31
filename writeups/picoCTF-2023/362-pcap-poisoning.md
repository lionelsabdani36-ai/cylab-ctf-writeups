# Writeup: PcapPoisoning (Challenge ID: 362)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Packet Analysis
- **Difficulty:** Medium (diff=2)
- **Event:** picoCTF 2023
- **Flag:** `academy{P64P_4N4L7S1S_SU55355FUL_7a51913b}`

---

## Problem Statement & Scope

Tantangan menyediakan file rekaman tangkapan lalu lintas jaringan (`trace.pcap`). Objektif investigasi adalah mengidentifikasi flag yang tersembunyi di dalam aliran paket data tanpa kredensial awal.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Unencrypted Cleartext Data Transmission (RFC 793 / NIST SP 800-115):** Transmisi data sensitif melalui protokol TCP tanpa enkripsi lapisan aplikasi (TLS) mengekspos seluruh isi payload paket kepada pengamat jaringan pasif atau analis forensik.
2. **Network Protocol Carving:** Pada analisis forensik jaringan, artefak plaintext dapat diidentifikasi secara langsung melalui inspeksi paket per frame atau ekstraksi string biner berbasis ekspresi reguler.
3. **Struktur Paket #507:** Flag berada pada payload TCP segmen #507 di port transmisi data, tanpa obfuscation atau kompresi tambahan.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh artefak: `trace.pcap` dari CDN CyLab Academy (`challenge-files.cylabacademy.net/library/...`).
2. Analisis biner/pcap menggunakan Python atau `strings` / Wireshark:
   ```bash
   strings trace.pcap | grep -E "(academy|picoCTF)\{"
   ```
3. Ekstraksi otomatis melalui skrip `scripts/solve_362_pcap_poisoning.py`.
4. Verifikasi token via REST API: `POST /api/submissions/` dengan payload `{"challenge": 362, "flag": "academy{P64P_4N4L7S1S_SU55355FUL_7a51913b}"}` menghasilkan HTTP Status 201 `correct: true`.

---

## Flag & Verifikasi

- **Flag:** `academy{P64P_4N4L7S1S_SU55355FUL_7a51913b}`
- **Bukti:** Submisi REST API `/api/submissions/` mengembalikan `{"correct": true, "historical": false}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS:** Penguasaan inspeksi PCAP, pemfilteran Wireshark/tshark (`tcp.payload contains "academy"`), serta string carving pada artefak pcapng/pcap.
- **Mitigasi Defensif:** Terapkan enkripsi end-to-end (TLS 1.3) pada semua kanal transmisi data sensitif untuk mencegah *eavesdropping* dan *sniffing* paket.
