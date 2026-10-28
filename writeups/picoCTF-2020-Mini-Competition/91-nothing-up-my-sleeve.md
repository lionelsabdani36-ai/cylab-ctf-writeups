# Writeup: Nothing Up My Sleeve (Challenge ID: 91)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Network Forensics
- **Difficulty:** Easy
- **Author:** Q0h313th
- **Event:** picoCTF 2020 Mini-Competition
- **Points:** 1
- **Flag:** `academy{c0ngr4ts_0n_y0ur_s4n1ty}`

---

## Problem Statement & Scope
Peserta diminta memeriksa konektivitas internet; flag berada *in-the-clear* (tidak terenkripsi). Disediakan file `flag.txt` untuk diunduh.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Transmisi Cleartext:** Data yang dikirim tanpa enkripsi (HTTP/FTP mentah, file teks polos) dapat dibaca siapa pun di jalur jaringan.
2. **Hygiene Unduhan:** File yang diunduh dari tautan langsung harus tetap diverifikasi (hash, sumber) walaupun isinya tampak sepele — ini melatih kebiasaan memeriksa ketersambungan sebelum mengerjakan soal berbasis jaringan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh `flag.txt` dari tautan challenge (atau via `wget` sesuai petunjuk):
   ```bash
   wget 'https://challenge-files.cylabacademy.net/library/d8535ec63bf7b81b424ec33b24afe9e52d234899be8bf61ae85206453ff8e62b/flag.txt'
   ```
2. Baca isi file:
   ```bash
   cat flag.txt
   ```
3. Flag langsung terlihat: `academy{c0ngr4ts_0n_y0ur_s4n1ty}`.

---

## Flag & Verifikasi
- **Flag:** `academy{c0ngr4ts_0n_y0ur_s4n1ty}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Enkripsi Transport:** Gunakan selalu TLS (HTTPS) dan hindari transfer kredensial/flag melalui HTTP polos.
- **Prinsip Least Surprise:** Jangan menaruh rahasia dalam file berlabel jelas; gunakan secret manager dengan kontrol akses.

---

## Solver
Lihat `scripts/solve_91_nothing_up_my_sleeve.py` — mengunduh `flag.txt` dan mencetak flag.
