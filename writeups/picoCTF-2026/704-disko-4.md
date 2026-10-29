# DISKO 4 (Challenge 704, Forensics)

- **ID:** 704 | **Event:** picoCTF 2026 | **Kategori:** Forensics | **Level:** Medium
- **Flag:** `academy{d3l_d0n7_h1d3_w3ll_9748d144}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`704.dd` (100 MB) adalah raw disk image. File `dont-delete.gz` sudah
DIHAPUS dari direktori — tetapi isinya masih utuh di unallocated space.
Carving dengan `icat` (sleuthkit, offset partisi 1140736) mengembalikan
gzip yang langsung mencetak flag saat diekstrak.

## Root Cause
Menghapus file hanya melepas directory entry/inode — blok data tetap ada
sampai ditimpa. Tanpa wipe/secure-erase, "deleted" ≠ "destroyed".
Pelajaran: recovery forensik = baca blok mentah, abaikan metadata filesystem.

## Rekonstruksi
1. `fls -o 1140736 704.dd` petakan filesystem; identifikasi inode bekas
   `dont-delete.gz` (atau `strings 704.dd | grep -i delete` untuk anchor).
2. `icat -o 1140736 704.dd <inode> > dont-delete.gz`.
3. `gzip -dc dont-delete.gz` → `Here is your flag / academy{d3l_d0n7_h1d3_w3ll_9748d144}`.
   Otomasi: `python3 scripts/solve_704_disko_4.py dont-delete.gz`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Untuk data sensitif gunakan full-disk encryption (LUKS/BitLocker) dan
secure-erase (overwrite + TRIM/discard); hapus biasa tidak cukup pada
media magnetik maupun flash (wear-leveling menyimpan salinan).

## Takeaway LKS
Klasifikasi Forensics: disk carving — bedakan directory entry vs data blok,
pakai sleuthkit (`fls`/`icat`) + `gzip`. Fondasi seri DISKO (1→4).
