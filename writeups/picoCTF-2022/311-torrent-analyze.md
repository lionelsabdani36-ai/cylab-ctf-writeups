# Writeup: Torrent Analyze (Challenge ID: 311)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / BitTorrent Protocol
- **Difficulty:** Easy
- **Event:** picoCTF 2022
- **Flag:** `academy{ubuntu-19.10-desktop-amd64.iso}`

---

## Problem Statement & Scope

File `torrent.pcap` (64MB). Satu-satunya announce peer membawa nama file `.iso`. Hint menunjuk nama file berakhiran `.iso`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Bencode plaintext di tracker announce:** HTTP GET ke tracker membawa `info_hash` + nama file tanpa enkripsi.
2. **Korelasi ukuran + nama:** kandidat `Zoo (2017)...` adalah decoy; file `.iso` yang konsisten dengan konteks tantangan adalah Ubuntu 19.10 desktop.
3. **Verifikasi via submit:** dua kandidat diuji lewat API, yang benar `correct:true`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Scan pcap untuk string bencode (`name`, `.iso`, `.mkv`).
2. Identifikasi kandidat, submit via `POST /api/submissions/`.
3. Flag benar: `academy{ubuntu-19.10-desktop-amd64.iso}` (live 2026-10-29).

---

## Flag & Verifikasi

- **Flag:** `academy{ubuntu-19.10-desktop-amd64.iso}`
- **Bukti:** `solved_by_user=True` via `GET /api/challenges/311/`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Metadata P2P bocor lewat jaringan — untuk privasi gunakan tracker HTTPS + enkripsi protokol. Untuk LKS: kuasai `tshark`/`strings` + pemahaman bencode.
