# Redaction gone wrong (Challenge 290, Forensics)

- **ID:** 290 | **Event:** picoCTF 2022 | **Kategori:** Forensics | **Level:** Easy (diff 2, 100 pts)
- **Flag:** `academy{C4n_Y0u_S33_m3_fully}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`Financial_Report_for_ABC_Labs.pdf` menampilkan baris `academy{...}` yang
tertutup kotak hitam ("Breakdown - Just painted over in MS word.").

## Root Cause
Redaksi hanya melukis rect hitam (`0 0 0 rg / n 69 428 192.096 17 re f*`)
DI ATAS teks; operator `Tj` berisi flag tetap ada di content stream
(ASCII85+Flate). Redaksi visual bukan redaksi data.

## Rekonstruksi
1. Unduh PDF dari CDN (URL di `GET /api/challenges/290/instance/`).
2. Ambil objek stream 8, ASCII85-decode lalu zlib-decompress.
3. Baca string `Tj`: baris `academy{C4n_Y0u_S33_m3_fully}` tepat sebelum
   operator rect hitam.
   Otomasi: `python3 scripts/solve_290_redaction.py <file.pdf>`.

## Mitigasi
Redaksi PDF yang benar menghapus objek teks/gambar dari content stream
(flatten + sanitasi), bukan menutupinya; verifikasi dengan ekstraksi teks
sebelum distribusi.

## Takeaway LKS
Forensik dokumen: render bukan kebenaran — periksa content stream;
kotak hitam adalah annotasi, bukan penghapusan.
