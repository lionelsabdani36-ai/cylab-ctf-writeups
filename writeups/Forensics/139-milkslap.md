# Writeup: Milkslap (Challenge ID: 139)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Image Manipulation
- **Difficulty:** Medium
- **Flag:** `academy{imag3_m4n1pul4t10n_sl4p5}`

---

## Problem Statement & Scope
Diberi file gambar hasil konkatenasi / manipulasi (`concat.png`, `raw.bin`). Target: ekstrak flag tersembunyi.

## Root Cause
Data gambar disambung (concatenation) sehingga viewer biasa hanya tampil sebagian; sisa byte berisi potongan flag.

## Exploit
```bash
# identifikasi batas file asli
xxd concat.png | tail
binwalk -e raw.bin
# atau split manual per magic byte PNG, lalu strings
strings potongan.bin | grep academy{
```

## Mitigasi
Validasi integritas file (magic byte + ukuran + hash) sebelum distribusi soal.

## Verifikasi
Submit via `/api/submissions/` → `correct:true`.
