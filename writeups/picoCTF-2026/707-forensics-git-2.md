# Forensics Git 2 (Challenge 707, Forensics)

- **ID:** 707 | **Event:** picoCTF 2026 | **Kategori:** Forensics | **Level:** Medium
- **Flag:** `academy{g17_r35cu3_16ac6bf3}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`707-disk.img` (1 GB) berisi repo `killer-chat-app` dengan `logs/1.txt`,
`2.txt`, `4.txt` — `3.txt` HILANG dari HEAD maupun semua branch. File itu
bertahan sebagai objek DANGLING (blob/commit tak ter-referensi) dan
`git fsck --lost-found` (atau `git log --all --full-history -- logs/3.txt`)
mengembalikannya; isi chat log memuat flag.

## Root Cause
Objek git tak ter-referensi tidak langsung dihapus — `git gc`/`prune`
berjalan periodik, dan image diambil sebelum itu. Dangling objects =
sisa artefak yang bisa di-rescue. Pelajaran: forensik git tidak berhenti
di `log`; `fsck` menemukan yang disembunyikan penghapusan.

## Rekonstruksi
1. Ekstrak repo dari image seperti 705/706.
2. `git fsck --lost-found` → catat hash dangling commit/blob.
3. `git show <hash>` satu per satu, grep `academy{` →
   `academy{g17_r35cu3_16ac6bf3}` (alternatif:
   `git log --all --full-history -- logs/3.txt`).
   Otomasi: `python3 scripts/solve_707_forensics_git_2.py <repo>`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
`git gc --prune=now --aggressive` + BFG/filter-repo untuk secret bocor,
lalu rotasi kredensial. Di sisi analis: selalu `fsck` sebelum menyerah.

## Takeaway LKS
Klasifikasi Forensics: recovery objek dangling (`fsck --lost-found`,
`show`, `log --full-history`). Penutup seri Git 705→707: HEAD → riwayat
→ tak-ter-referensi.
