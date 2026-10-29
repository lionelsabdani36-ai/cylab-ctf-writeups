# Eavesdrop (Challenge 264, Forensics)

- **ID:** 264 | **Event:** picoCTF 2022 | **Kategori:** Forensics / PCAP Analysis | **Level:** Medium
- **Flag:** `academy{nc_73115_411_02612719}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`capture.flag.pcap`: obrolan chat pada TCP port 9001 membocorkan
perintah dekripsi `openssl des3 -d -salt -in file.des3 -out file.txt
-k supersecretpassword123`, sementara blob DES3 (header `Salted__`)
ditransfer lewat TCP port 9002.

## Root Cause
Dua stream TCP terpisah: 9001 = kontrol (chat + perintah openssl +
password `supersecretpassword123`), 9002 = data (blob DES3 mentah
48 byte diawali `Salted__`). Rekonstruksi = gabungkan payload TCP
port 9002 sesuai urutan paket, tulis sebagai `file.des3`, lalu
`openssl des3 -d -salt -k ...` → `file.txt` berisi flag. Parser
solver membaca pcap global-header 24 byte + per-paket header 16
byte (`<IIII`), memfilter IPv4/TCP, dan menggabung payload segmen
dengan sport/dport 9002 (offset header TCP dari data-offset nibble).

## Rekonstruksi
1. Unduh `capture.flag.pcap` dari CDN challenge-files.
2. Baca chat port 9001 → dapatkan perintah + password DES3.
3. Reassemble stream port 9002 → `file.des3` (48 byte, `Salted__`).
4. `openssl des3 -d -salt -in file.des3 -out file.txt -k
   supersecretpassword123` → flag di `file.txt`. Otomasi:
   `python3 scripts/solve_264_eavesdrop.py [capture.flag.pcap]`
   (terverifikasi: blob 48 byte, flag tercetak).
5. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Jangan kirim password dekripsi di channel yang sama/tidak terenkripsi
dengan data terenkripsi; gunakan TLS untuk kontrol + data, password
via KDF (bukan `-k` string langsung di command line yang tercatat di
history), dan forward secrecy agar satu pcap bocor tidak membuka
seluruh arsip.

## Takeaway LKS
Klasifikasi Forensics: anatomi pcap (global/packet header), parsing
IPv4/TCP manual (IHL, ports, data offset), reassemble stream TCP, dan
dekripsi simetris DES3 dengan salt. Relevan defensif: mengapa
password-in-chat menggagalkan enkripsi data-at-rest.
