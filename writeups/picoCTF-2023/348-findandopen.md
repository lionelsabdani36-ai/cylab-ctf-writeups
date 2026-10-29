# Writeup: FindAndOpen (Challenge ID: 348)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / PCAP + ZipCrypto
- **Difficulty:** Easy
- **Event:** picoCTF 2023
- **Flag:** `academy{R34DING_LOKd_fil56_succ3ss_9989a41b}`

---

## Problem Statement & Scope

File `dump.pcap` (frame Ethernet palsu, payload ASCII) + `flag.zip` (1 file `flag` 45 byte, ZipCrypto). Aliran decoy: `Could the flag have been splitted?`, `Maybe try checking the other file`, `ababab...`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Covert channel via frame palsu:** MAC + ethertype + payload adalah ASCII yang bisa di-decode langsung.
2. **Prefix flag sebagai password:** aliran `AABBHHPJGTFRLK` + base64 decode = `This is the secret: academy{R34DING_LOKd_` — itu password ZipCrypto, BUKAN flag.
3. **ZipCrypto lemah:** password diketahui → unzip langsung membuka isi.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Dump semua printable dari pcap, decode base64 per aliran.
2. Identifikasi password dari aliran secret.
3. `unzip -P 'academy{R34DING_LOKd_' flag.zip` → baca file `flag` (45 byte).
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

---

## Flag & Verifikasi

- **Flag:** `academy{R34DING_LOKd_fil56_succ3ss_9989a41b}`
- **Bukti:** `solved_by_user=True` via `GET /api/challenges/348/`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Jangan simpan password di kanal yang sama dengan data terproteksi; gunakan AES-256 + KDF (Argon2). Untuk LKS: kuasai ekstraksi string pcap + bedakan password vs flag.
