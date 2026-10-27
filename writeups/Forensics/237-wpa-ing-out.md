# Writeup: WPA-ing Out (Challenge ID: 237)

- **Platform:** CyLab Security Academy
- **Category:** Forensics / Wireless 802.11 & WPA2-PSK Handshake
- **Difficulty:** Medium
- **Points:** 200
- **Flag:** `academy{mickeymouse}`

---

## Problem Statement & Scope
Diberikan packet capture `wpa-ing-out.pcap` yang merekam lalu lintas jaringan nirkabel. Peserta diminta memecahkan passphrase WiFi target.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **WPA2 4-Way Handshake Vulnerability:** Pertukaran 4-way EAPOL handshake memvalidasi Pairwise Transient Key (PTK) yang diturunkan dari Pre-Shared Key (PSK). Jika passphrase lemah, serangan offline dictionary dapat dilakukan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Filter paket EAPOL pada Wireshark untuk SSID `Gone_Surfing`.
2. Jalankan `aircrack-ng -w rockyou.txt wpa-ing-out.pcap`.
3. Kunci terpecahkan: `mickeymouse`.
4. Format flag: `academy{mickeymouse}`.

---

## Flag & Verifikasi
- **Flag:** `academy{mickeymouse}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **WPA3-Enterprise Migration:** Terapkan WPA3 dengan SAE untuk mencegah offline dictionary attacks.
