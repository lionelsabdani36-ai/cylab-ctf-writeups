# Writeup: DISKO 3 (Challenge ID: 507)

- **Platform:** CyLab Security Academy
- **Category:** Forensics / FAT32 Filesystem & Hidden Archive
- **Difficulty:** Easy
- **Points:** 1
- **Flag:** `academy{n3v3r_z1p_2_h1d3_2f899900}`

---

## Problem Statement & Scope
Diberikan raw disk image `disko-3.dd`. Peserta diminta mencari data sensitif yang tersembunyi di dalam struktur sistem berkas.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Archive Concealment in System Logs:** Berkas kompresi non-standar `flag.gz` disamarkan di antara tumpukan log sistem `/var/log` pada volume FAT32.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Mount atau periksa image dengan `7z l disko-3.dd` atau `fls`.
2. Periksa direktori `log/` dan temukan arsip `flag.gz`.
3. Ekstrak dan dekompresi `flag.gz` untuk mendapatkan flag.

---

## Flag & Verifikasi
- **Flag:** `academy{n3v3r_z1p_2_h1d3_2f899900}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Log Integrity Monitoring:** Pasang File Integrity Monitoring (FIM) untuk memonitor perubahan tidak sah di direktori logging.
