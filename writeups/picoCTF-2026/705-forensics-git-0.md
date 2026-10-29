# Forensics Git 0 (Challenge 705, Forensics)

- **ID:** 705 | **Event:** picoCTF 2026 | **Kategori:** Forensics | **Level:** Medium
- **Flag:** `academy{g17_1n_7h3_d15k_041217d8}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`705-disk.img` (1 GB) adalah raw disk image berisi repo git
(`/home/user/...`). Setelah ekstraksi filesystem (sleuthkit `fls`/`icat`,
offset 1140736), `git log` biasa di repo hasil recovery langsung
menampilkan commit message yang ISINYA flag.

## Root Cause
Flag di-commit sebagai plaintext lalu image didistribusikan — riwayat git
adalah arsip permanen. `git log` membaca objek commit tanpa perlu trik.
Pelajaran: jangan commit secret; git tidak pernah lupa (meski file
dihapus, objek tetap ada sampai gc/prune).

## Rekonstruksi
1. Ekstrak filesystem dari image (`fls`/`icat` atau mount loop + offset).
2. `cd <repo> && git log --format='%H %s'` → temukan commit ber-flag.
3. Catat `academy{g17_1n_7h3_d15k_041217d8}`.
   Otomasi: `python3 scripts/solve_705_forensics_git_0.py <repo>`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Scan pre-commit (gitleaks/trufflehog), revoke secret yang terlanjur
ter-commit, dan rewrite history (BFG/filter-repo) + rotasi kredensial.

## Takeaway LKS
Klasifikasi Forensics: git sebagai artefak forensik — `git log/show`
adalah langkah pertama sebelum fsck/checkout/dangling. Pembuka seri
Forensics Git 0→2.
