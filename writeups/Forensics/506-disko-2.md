# Writeup: DISKO 2 (Challenge ID: 506)

- **Platform:** CyLab Security Academy
- **Category:** Forensics / Disk Image & MBR Partition Analysis
- **Difficulty:** Easy
- **Points:** 1
- **Flag:** `academy{4_P4Rt_1t_i5_51b913f5}`

---

## Problem Statement & Scope
Diberikan raw disk image `disko-2.dd`. Peserta harus menganalisis struktur partisi dan menemukan flag yang tersembunyi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Decoy Partitioning:** Disk memuat partisi FAT32 yang diisi ratusan flag palsu/umpan untuk membingungkan analisis string otomatis.
2. **MBR Partition Table Analysis:** Partisi sebenarnya adalah partisi Linux Native (Type 0x83) yang berada pada sektor 2048.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis tabel partisi menggunakan `fdisk -l disko-2.dd` atau `mmls`.
2. Identifikasi Partisi 1 (Linux Native) pada offset 2048 sektor.
3. Ekstrak sektor partisi Linux menggunakan `dd` atau `fls`/`icat`.
4. Temukan file flag autentik di dalam partisi Linux tersebut.

---

## Flag & Verifikasi
- **Flag:** `academy{4_P4Rt_1t_i5_51b913f5}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Forensic Verification:** Selalu verifikasi tipe sistem berkas dan struktur partisi MBR/GPT secara holistik sebelum mempercayai artefak string.
