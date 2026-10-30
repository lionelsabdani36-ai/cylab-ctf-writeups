# 367 — ReadMyCert (picoCTF 2023, Cryptography, Medium)

## Challenge Metadata
- ID: 367 | Event: picoCTF 2023 | Author: Sunday Jacob Nwanyim
- Kategori: Cryptography | Difficulty: Medium (2)
- Flag: `academy{read_mycert_a209fd00}`
- Status: SOLVED (POST /api/submissions/ -> `correct: true`)

## Problem Statement & Scope
Challenge statis (on_demand false, tanpa instance): unduh file CSR
`readmycert.csr` dari CDN challenge-files dan baca isinya. Hint:
"Download the certificate signing request and try to read it."

## Teori & Akar Kerentanan (Root Cause)
Certificate Signing Request (CSR, format PKCS#10, RFC 2986) menyimpan
metadata plaintext: Subject (CN, O, OU), kunci publik, dan atribut.
CSR tidak dienkripsi — siapa pun bisa membaca Subject dengan
`openssl req -text`. Flag ditempatkan langsung di Common Name (CN),
sehingga tidak ada kriptografi yang perlu dipecahkan; tantangannya
murni pengenalan format dan tooling X.509.

## Rekonstruksi Pengujian Terstruktur
1. Query instance (`GET /api/challenges/367/instance/`): `on_demand:
   false`, description berisi link CDN `readmycert.csr`.
2. Unduh CSR (997 byte, PEM `BEGIN CERTIFICATE REQUEST`).
3. `openssl req -in readmycert.csr -text -noout` -> baris Subject:
   `CN=academy{read_mycert_a209fd00}, name=ctfPlayer`.
4. Submit via `POST /api/submissions/` -> `201 {"correct": true}`.

## Flag & Verifikasi
- Flag resmi: `academy{read_mycert_a209fd00}`
- Verifikasi: `201 {"challenge": 367, "correct": true, "historical": false}`

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Jangan pernah menyimpan data sensitif di field sertifikat/CSR yang
  readable publik (CN, SAN, OU); sertifikat bersifat public-by-design.
- Kuasai tooling: `openssl req/x509 -text`, `openssl asn1parse` untuk
  forensik sertifikat di LKS (jejak C2, phishing cert).
- Solver reproduktif: `scripts/solve_367_readmycert.py` (stdlib +
  openssl CLI, tanpa instance).
