# Writeup: Ph4nt0m 1ntrud3r (Challenge ID: 459)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Network Traffic & Timing Analysis
- **Difficulty:** Easy
- **Event:** picoCTF 2025
- **Points:** 50
- **Flag:** `academy{1t_w4snt_th4t_34sy_tbh_4r_dd2075f0}`

---

## Problem Statement & Scope
Diberikan file penangkapan paket jaringan `myNetworkTraffic.pcap`. Peserta diminta menganalisis anomali lalu lintas jaringan untuk mengungkap transmisi rahasia.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Timing Covert Channel:** Eksfiltrasi data dilakukan dengan mengirim paket pada interval waktu mikrodetik yang teratur (~107 us) untuk menghindari deteksi berbasis signature.
2. **Fragmented Base64 Payload:** Data flag dipecah ke dalam beberapa muatan TCP segmen kecil.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Buka `myNetworkTraffic.pcap` menggunakan Wireshark atau Scapy.
2. Filter paket TCP dengan interval waktu mikrodetik yang konsisten.
3. Ekstrak payload dari paket-paket tersebut dan gabungkan muatan Base64.
4. Decode Base64 untuk mendapatkan flag lengkap.

---

## Flag & Verifikasi
- **Flag:** `academy{1t_w4snt_th4t_34sy_tbh_4r_dd2075f0}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Behavioral NIDS:** Terapkan deteksi anomali perilaku trafik (Zeek/Suricata) untuk mendeteksi timing covert channel.
