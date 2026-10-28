# Writeup: Wireshark twoo twooo two twoo... (Challenge ID: 110)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / DNS Exfiltration
- **Difficulty:** Easy
- **Author:** Dylan
- **Event:** picoCTF 2021
- **Points:** 100
- **Flag:** `academy{dns_3xf1l_ftw_deadbeef}`

---

## Problem Statement & Scope
Disediakan `shark2.pcapng` (~3,5 MB). Petunjuk: "did you really find _the_ flag?" (umpan: banyak string `academy{...}` palsu di dalam capture) dan "look for traffic that seems suspicious".

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Eksfiltrasi via DNS:** Data rahasia dienkode (di sini base64) menjadi label subdomain dan dikirim sebagai query DNS ke nameserver penyerang — lolos dari firewall yang hanya memfilter TCP/HTTP.
2. **Decoy & Validasi:** Capture berisi lusinan flag palsu; hanya rekonstruksi jalur eksfiltrasi (query ke IP tujuan yang konsisten, domain `reddshrimpandherring`) yang menghasilkan flag asli.
3. **Parsing Tanpa Wireshark:** Header pcapng + parsing DNS manual (struct) cukup untuk ekstraksi deterministik.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Pindai semua paket; saring query DNS (UDP dport 53, QR=0) menuju `18.217.1.57` dengan nama mengandung `reddshrimpandherring`.
2. Ambil label pertama tiap query secara berurutan; gabungkan menjadi satu blob base64.
3. Decode base64 → flag asli: `academy{dns_3xf1l_ftw_deadbeef}` (flag palsu yang tersebar diabaikan karena tidak berasal dari jalur eksfiltrasi).

---

## Flag & Verifikasi
- **Flag:** `academy{dns_3xf1l_ftw_deadbeef}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Monitoring DNS:** Log dan anomali-deteksi query DNS (entropi label tinggi, volume ke domain baru) untuk menangkap eksfiltrasi.
- **DNS Filtering/Response Policy:** Blokir domain tidak dikenal; pertimbangkan DNS-over-HTTPS inspection di perimeter.
- **Jangan Percaya String Acak:** Verifikasi flag melalui kanal resmi (submit API), bukan kemunculan string di capture.

---

## Solver
Lihat `scripts/solve_110_wireshark_twoo.py` — mengekstrak dan men-decode eksfiltrasi DNS menjadi flag.
