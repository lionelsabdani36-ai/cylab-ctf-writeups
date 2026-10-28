# Writeup: c0rrupt (Challenge ID: 53)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / File Carving & PNG Repair
- **Difficulty:** Easy (2)
- **Author:** Danny
- **Event:** picoCTF 2019
- **Points:** 250
- **Flag:** `academy{c0rrupt10n_1847995}`

---

## Problem Statement & Scope
Diberikan berkas `c0rrupt-mystery` — seharusnya gambar PNG berisi flag, tetapi header rusak sehingga tidak bisa dibuka penampil gambar. Tugas: perbaiki struktur dan pulihkan piksel untuk membaca flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Struktur PNG:** Magic `89 50 4E 47 0D 0A 1A 0A`, lalu deretan chunk `len(4) + type(4) + data + crc(4)`. Berkas ini punya magic rusak (`89 65 4E 34...`) dan chunk length/type pertama korup (`AA AA FF A5` / `AB DET`).
2. **zlib Stream Splicing:** Data gambar PNG adalah satu aliran zlib yang dipecah ke beberapa chunk IDAT. Tiga IDAT di offset `0x10008/0x20008/0x30008` valid; payload pertama (bytes `0x5B..0x10000`) menyimpan awal aliran meski header chunk-nya rusak. Penggabungan keempatnya + dekompresi raw-deflate menghasilkan tepat `1095*(1+1642*3) = 5395065` bytes — bukti rekonstruksi benar.
3. **PNG Unfiltering:** Tiap baris diawali byte filter (None/Sub/Up/Average/Paeth); terapkan invers untuk dapat RGB 1642x1095. Flag berada di pita baris 33..576.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh artefak:
   ```bash
   curl -sL -O https://challenge-files.cylabacademy.net/library/8388ecc430588d15064755583476bec46e23d42a6d8de6e8995c19e40f2e4c58/c0rrupt-mystery
   ```
2. Periksa header: magic `89 65 4E 34` (harusnya `89 50 4E 47`), panjang chunk pertama `AA AA FF A5` (tidak valid), tipe `AB 44 45 54` (harusnya `IDAT`).
3. Gabungkan `data[0x5B:0x10000]` + 3 payload IDAT valid → `zlib.decompress(wbits=-15)` → tepat 5395065 bytes.
4. Terapkan unfilter Paeth/Sub/Up/Average per baris → RGB 1642x1095; pita gelap di baris 33..576.
5. Render crop pita (821x230) dan baca teks overlay → `academy{c0rrupt10n_1847995}`.

---

## Flag & Verifikasi
- **Flag:** `academy{c0rrupt10n_1847995}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201); GET `/api/challenges/53/` menunjukkan `solved_by_user: true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Decode Tanpa PIL:** Kuasai `struct + zlib + unfilter` manual — lingkungan lomba tidak selalu punya pustaka gambar.
- **Validasi Ukuran Dekompresi:** `H*(1+W*3)` adalah checksum gratis kebenaran rekonstruksi aliran zlib.
- **Mitigasi:** Korupsi header bukan enkripsi — siapa pun bisa memperbaiki. Jangan andalkan "rusak" sebagai proteksi; gunakan enkripsi sejati untuk data sensitif.
