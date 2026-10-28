# Writeup: shark on wire 2 (Challenge ID: 84)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Packet Analysis
- **Difficulty:** Medium
- **Author:** Danny
- **Event:** picoCTF 2019
- **Points:** 200
- **Flag:** `academy{p1LLf3r3d_data_v1a_st3g0}`

---

## Problem Statement & Scope
Disediakan file capture `.pcap` (±112 KB). Tugas: menemukan aliran data tersembunyi di antara trafik decoy (TCP/UDP biasa) dan merekonstruksi flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Eksfiltrasi via field protokol:** penyerang menyandikan 1 byte data per paket pada field yang jarang diawasi — di sini `UDP.dstport == 22` sebagai penanda, dengan byte data = `UDP.srcport - 5000` (karakter ASCII).
2. **Marker framing:** aliran diawali paket `start` dan diakhiri `end` agar decoder tahu batas sekuens; paket di luar marker adalah decoy.
3. **Pola resmi komunitas:** filter Wireshark `udp.dstport==22`, lalu `chr(udp.srcport-5000)` per paket berurutan — teknik "pilfered data via stego" yang memberi nama flag (`p1LLf3r3d` = pilfered).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Challenge statis (`on_demand=false`): unduh pcap dari CDN.
2. Inventarisasi: 1 koneksi TCP + banyak paket UDP; abaikan TCP dan paket UDP 1-char.
3. Filter paket UDP dengan `dport == 22` di antara marker `start`/`end`.
4. Untuk tiap paket berurutan: `chr(sport - 5000)` → rangkai menjadi `academy{p1LLf3r3d_data_v1a_st3g0}`.
5. Submit via API → `correct: true`.

---

## Flag & Verifikasi
- **Flag:** `academy{p1LLf3r3d_data_v1a_st3g0}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Analisis field-by-field:** saat payload terlihat acak, curigai field header (port, seq, ID) sebagai kanal eksfiltrasi.
- **Buat filter bertingkat:** pisahkan marker/framing dulu, baru decode — mengabaikan decoy sejak awal.
- **Mitigasi:** IDS/egress-filtering yang memantau anomali port (mis. UDP ke port 22/SSH) dapat mendeteksi kanal semacam ini.

---

## Solver
Lihat `scripts/solve_84_shark_on_wire_2.py` — mem-parsing pcap (stdlib saja), memfilter aliran penanda, dan merekonstruksi flag.
