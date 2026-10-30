# 169 - It is my Birthday 2 (Cryptography, picoCTF 2021, Medium)

## Challenge Metadata
- ID: 169 | Event: picoCTF 2021 | Author: Sara/madStacks
- Category: Cryptography | Difficulty: Medium (2)
- Flag: `academy{h4ppy_b1rthd4y_2_m3_8248ffdd}`

## Problem Statement & Scope
Lab on-demand: form upload 2 file (`file1`, `file2`). Server menuntut:
PDF valid dan berbeda, SHA1 identik, dan 1000 byte terakhir keduanya
sama dengan 1000 byte terakhir `invite.pdf` (2.2 MB). Lolos -> flag di
flash message halaman index.

## Teori & Akar Kerentanan (Root Cause)
1. SHA1 rentan collision chosen-prefix sejak SHAttered (2017, Google/CWI):
   pasangan publik `shattered-1.pdf` / `shattered-2.pdf` (422435 byte,
   SHA1 sama `38762cf7...`, konten beda).
2. SHA1 = konstruksi Merkle-Damgard: suffix identik yang di-append ke
   dua pesan ber-collision MEMPERTAHANKAN collision (length extension).
   Jadi `base_i + invite_tail` tetap sama-SHA1 untuk i=1,2 sekaligus
   memenuhi syarat ekor-1000.
3. "Birthday attack" di judul menyesatkan (hint resmi: "This isn't
   REALLY a birthday attack") — solusi memakai collision konkret,
   bukan brute force ulang tahun.

## Rekonstruksi Eksploitasi Step-by-Step
1. `PUT /api/challenges/169/instance/` -> RUNNING
   `chatelaine.cylabacademy.net:31494`; unduh `invite.pdf` CDN.
2. Unduh `https://shattered.io/static/shattered-{1,2}.pdf`;
   verifikasi SHA1 sama + konten beda.
3. Append `invite[-1000:]` ke keduanya -> `upload{1,2}.pdf` (423435 byte,
   SHA1 sama `133f99dc...`, ekor cocok).
4. `POST /upload` multipart, ikuti 302 dengan session cookie -> index
   menampilkan `Flag: academy{...}`.
5. Submit `POST /api/submissions/` -> `correct: true`; `DELETE` instance.

## Flag & Verifikasi
- `academy{h4ppy_b1rthd4y_2_m3_8248ffdd}` (`correct: true`, historical false).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Jangan pakai SHA1/MD5 untuk integritas anti-pemalsuan; migrasi ke
  SHA-256/384 + tanda tangan (HMAC/RSA-PSS) bila butuh unforgeability.
- Validasi "file berbeda tapi hash sama" justru MENGUNDANG collision;
  bandingkan byte konten + tolak duplikat hash untuk dokumen unik.
- Defensif: verifikasi PDF (magic, xref, render) + simpan hash SHA-256
  sisi server sebagai identitas kanonis.
