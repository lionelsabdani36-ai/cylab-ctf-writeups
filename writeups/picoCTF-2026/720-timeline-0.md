# Timeline 0 (Challenge 720, Forensics)

- **ID:** 720 | **Event:** picoCTF 2026 | **Kategori:** Forensics | **Level:** Easy
- **Flag:** `academy{71m311n3_0u7113r_h3r_43a2e7af}` (carving lokal + base64 OK;
  submit API `{"correct": true}` status 201)

## Skenario
Diberikan disk image `partition4.img.gz` (ext4, ~490MB). Tugas: temukan
flag di dalam image, bungkus dengan format `academy{}`.
Petunjuk: "Create a Sleuthkit MAC timeline!" dan "Sloppy timestomping can
yield strange (very old) timestamps".

## Root Cause
MAC timeline (Modified/Accessed/Changed/Birth) merekonstruksi urutan
aktivitas dari metadata inode. Anti-forensik "timestomping" mengubah
timestamp untuk menyembunyikan file, tetapi pelaku ceroboh yang mengatur
waktu ke masa lalu yang absurd (1985 — sebelum filesystem dibuat) justru
menciptakan anomali yang mudah dideteksi: file dengan mtime tertua di
seluruh image otomatis menjadi tersangka utama.

## Rekonstruksi
1. `gzip -dc partition4.img.gz > p720.img`; verifikasi `file` → ext4.
2. `fls -r -m / -o 0 p720.img | mactime -d > tl.csv` (bodyfile→timeline).
3. Urutkan tanggal: satu entri menonjol — `1985-01-01, /bin/bcab`
   (inode 4945), satu-satunya file pra-2020.
4. `icat -o 0 p720.img 4945` → blob Base64
   `NzFtMzExbjNfMHU3MTEzcl9oM3JfNDNhMmU3YWYK`.
5. `base64 -d` → `71m311n3_0u7113r_h3r_43a2e7af` → bungkus `academy{...}`.
6. Submit `POST /api/submissions/` → `{"correct": true}` (201).
   Otomasi: `python3 scripts/solve_720_timeline_0.py [image]`.

## Mitigasi
Gunakan secure timestamping / append-only logging agar manipulasi metadata
terdeteksi secara kriptografis; monitor anomali distribusi timestamp.

## Takeaway LKS
Klasifikasi Forensics: analisis MAC timeline Sleuthkit (`fls`, `icat`,
`mactime`) — deteksi timestomping via outlier statistik. Pola "file asing
dengan timestamp mustahil" bersama hidden payload & deleted-realloc.
