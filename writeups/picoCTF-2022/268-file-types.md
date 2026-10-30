# File types (Challenge 268, Forensics)

- **ID:** 268 | **Event:** picoCTF 2022 | **Kategori:** Forensics / File Format Nesting | **Level:** Medium
- **Flag:** `academy{f1len@m3_m@n1pul@t10n_f0r_0b2cur17y_35957b68}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`Flag.pdf` tidak bisa dibuka PDF reader. `file` menyebutnya `shell archive text`: arsip shar GNU sharutils berisi satu file `flag` yang di-uuencode. Hint resmi: "some file types can contain and nest other files".

## Root Cause
File adalah rantai nesting 10 lapis: shar -> uuencode -> `ar` -> `cpio` (newc) -> bzip2 -> gzip -> lzip -> LZ4 frame -> LZMA (ALONE) -> lzop -> lzip -> XZ -> teks hex dua baris -> ASCII. Tiap lapis hanya terdeteksi lewat magic bytes (`file`), bukan ekstensi. Referensi: NIST SP 800-115 (forensic media analysis), RFC 1952 (gzip), format lzip 6-byte header + LZMA1 RAW.

## Rekonstruksi
1. `file Flag.pdf` -> shell archive; ekstrak body uuencode (`^begin 600 flag` .. `end`), decode UU (catatan: backtick = 0, mask `& 0x3F`) -> magic `!<arch>`.
2. `ar` SysV/GNU biasa (`!<arch>`, entry `flag/` 1024 byte) berisi **binary cpio** little-endian (magic `070707` = byte `c7 71`): header 26 byte berisi 13 short LE (namesize=5, filesize=509; filesize = `(w0 << 16) | w1`), nama `flag\0`, pad genap -> payload 509 byte = bzip2. (Bukan BSD `#1/` dan bukan newc ASCII.)
3. `bz2.decompress` -> gzip -> `gzip.decompress` -> lzip 327 byte -> decode lzip: header `LZIP ver(1) dict(1) + 3 byte`, stream = `body[6:-20]`, LZMA1 RAW dict 4096 lc=3 lp=0 pb=2 (`lz4 -d -c` butuh flag `-c` untuk stdout; `lzop -d -o <out> <in.lzo>` butuh ekstensi `.lzo`) -> 281 byte.
4. Magic `LZ4 frame` -> `lz4 -d` (264 byte) -> LZMA ALONE -> `FORMAT_ALONE` -> 253 byte lzop.
5. `lzop -d` -> lzip 195 byte -> decode lzip (parameter sama) -> XZ 152 byte -> `FORMAT_XZ` -> teks hex 110 byte.
6. `bytes.fromhex` per baris -> `academy{f1len@m3_m@n1pul@t10n_f0r_0b2cur17y_35957b68}`.
   Otomasi: `python3 scripts/solve_268_file_types.py Flag.pdf` (+ `lz4`/`lzop` untuk lapis tengah).
7. Submit `POST /api/submissions/` -> `correct: true` (live 2026-10-30).

## Mitigasi
Validasi tipe file via magic bytes di sisi server, bukan ekstensi; tolak polyglot/nested-archive upload; batasi kedalaman dekompresi (decompression bomb guard); scan berlapis dengan `file` + sandbox ekstraksi.

## Takeaway LKS
Klasifikasi Forensics: identifikasi magic -> ekstraksi berlapis -> verifikasi tiap tahap. Relevan defensif: pemahaman format file mencegah bypass filter upload dan analisis malware berlapis.
