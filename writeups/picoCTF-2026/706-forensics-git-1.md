# Forensics Git 1 (Challenge 706, Forensics)

- **ID:** 706 | **Event:** picoCTF 2026 | **Kategori:** Forensics | **Level:** Medium
- **Flag:** `academy{g17_r3m3mb3r5_d4ddf904}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
`706-disk.img` (1 GB) berisi repo git yang sama gayanya. Bedanya: flag
TIDAK ada di HEAD — commit terbaru menghapus/menimpa file `secrets`.
Solusinya: `git log --all --oneline`, `git checkout` commit lama, baca
file secret versi lama.

## Root Cause
Penghapusan file di commit baru tidak menghapus objek blob/commit lama.
Riwayat git = time machine; checkout versi lama mengembalikan konten.
Pelajaran: "menghapus secret di commit berikut" tidak membersihkan
riwayat — objek lama tetap bisa di-show.

## Rekonstruksi
1. Ekstrak repo dari image seperti 705.
2. `git log --all --oneline` → daftar commit; `git checkout <old>` atau
   `git show <commit>:<path>` per commit, grep `academy{`.
3. Commit lama berisi `academy{g17_r3m3mb3r5_d4ddf904}`.
   Otomasi: `python3 scripts/solve_706_forensics_git_1.py <repo>`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Sama seperti 705: gitleaks pre-commit + BFG/filter-repo + rotasi secret.
Edukasi: `git rm` ≠ lupa; hanya rewrite history yang membersihkan.

## Takeaway LKS
Klasifikasi Forensics: navigasi riwayat (`log/checkout/show <rev>:<path>`).
Level 2 dari seri Git: 705 = HEAD, 706 = commit lama, 707 = dangling.
