# Writeup: Pitter, Patter, Platters (Challenge ID: 87)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Disk Image & Slack Space
- **Difficulty:** Easy
- **Author:** syreal
- **Event:** picoCTF 2020 Mini-Competition
- **Points:** 250
- **Flag:** `academy{b3_5t111_mL|_<3_d18a1e1e}`

---

## Problem Statement & Scope
Disediakan image partisi disk `suspicious.dd.sda1` yang dicurigai menyimpan data tersembunyi. Ditambah dua petunjuk: analisis image dalam beberapa cara (sebagai blob dan sebagai disk yang di-mount), dan fenomena *slack space* dengan toolset yang kini tersedia di Ubuntu.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Slack Space:** Sistem file mengalokasikan ruang per *cluster*; sisa ruang antara akhir file dan akhir cluster (*slack*) tetap menyimpan data lama. Data rahasia dapat disembunyikan di sana tanpa terlihat pada direktori normal.
2. **Analisis Multi-Lapis Forensik:** File yang tampak biasa (blob terkompresi/terenkripsi pada pandangan pertama) dapat di-mount sebagai filesystem untuk mengungkap struktur partisi sebenarnya.
3. **Tooling Modern:** Tool seperti `tsk_recover`, `blkls`/`blkcat` (Sleuth Kit) dan `slackspace` memeriksa area slack secara sistematis.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh `suspicious.dd.sda1` dari tautan challenge.
2. Identifikasi tipe image (`file suspicious.dd.sda1`) dan coba mount sebagai filesystem loopback.
3. Jelajahi isi partisi; temukan file/archive yang tampak rusak atau berpassword.
4. Periksa *slack space* partisi (mis. dengan `blkls` dari Sleuth Kit atau dengan memindai byte di luar batas file) untuk mengekstrak fragmen tersembunyi.
5. Rangkai fragmen hingga membentuk flag: `academy{b3_5t111_mL|_<3_d18a1e1e}`.

---

## Flag & Verifikasi
- **Flag:** `academy{b3_5t111_mL|_<3_d18a1e1e}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Sanitasi Media Penyimpanan:** Lakukan *secure wipe* (mis. `wipe`, `shred`, atau degaussing) sebelum disk dipindahtangankan agar slack space tidak membocorkan data.
- **Kebijakan Retensi Data:** Terapkan enkripsi *full-disk* (LUKS/BitLocker) sehingga sisa slack tetap tidak terbaca tanpa kunci.
- **Prosedur Chain-of-Custody Forensik:** Selalu bekerja pada salinan image dan dokumentasikan hash (SHA-256) sebelum dan sesudah analisis.

---

## Solver
Lihat `scripts/solve_87_pitter_patter_platters.py` — memeriksa slack space image disk dan mengekstrak flag.
