# 126 — Binary Gauntlet 1 (picoCTF 2021, Binary Exploitation, Medium)

## Challenge Metadata
- ID: 126 | Event: picoCTF 2021 | Author: (CyLab Academy)
- Kategori: Binary Exploitation | Difficulty: Medium (2)
- Flag: `fa9a2d95e569c1fff8525782765f2a13` (TANPA wrapper `academy{}`, sesuai deskripsi)
- Status: SOLVED (POST /api/submissions/ -> `correct: true`)

## Problem Statement & Scope
Lab netcat on-demand: binary `gauntlet` mencetak alamat stack buffer (`%p`),
membaca 2 baris ke heap, lalu `strcpy()` baris kedua ke buffer stack 112
byte -> overflow. GNU_STACK RWE (executable stack), tanpa canary. Deskripsi
menegaskan flag TIDAK memakai wrapper `academy{}` standar (raw hex string).

## Teori & Akar Kerentanan (Root Cause)
Stack buffer overflow klasik via `strcpy` tanpa batas (CWE-120/121): RIP
terkontrol pada offset 120 dari awal buffer. Karena stack executable (RWE)
dan alamat buffer dibocorkan di banner, serangan `ret2shellcode` langsung
bekerja: shellcode null-free `execve("/bin/sh")` 27 byte di awal buffer +
padding + ret = alamat buffer. Trunkasi NUL oleh `strcpy` tidak berbahaya
karena alamat stack/userspace berbagi byte tinggi `00 00`.

## Rekonstruksi Pengujian Terstruktur
1. Launch instance (`PUT /api/challenges/126/instance/`), poll hingga
   `RUNNING`, parse `nc -v xebec.cylabacademy.net 21646` dari description.
2. Unduh binary `gauntlet` dari CDN challenge-files untuk analisis offset
   (RIP = buf+120).
3. Jalankan solver: baca banner -> parse alamat `0x...` -> kirim `hello` ->
   kirim shellcode+pad+ret -> `cat flag.txt`.
4. Terima flag raw: `fa9a2d95e569c1fff8525782765f2a13`.
5. Submit via `POST /api/submissions/` -> `201 {"correct": true}`.

## Flag & Verifikasi
- Flag resmi: `fa9a2d95e569c1fff8525782765f2a13`
- Verifikasi: `201 {"challenge": 126, "correct": true, "historical": false}`

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Jangan pernah pakai `strcpy`/`gets` ke buffer stack; gunakan `strncpy`/
  `fgets` dengan batas eksplisit. Compile dengan canary (`-fstack-protector`),
  NX stack, dan ASLR/PIE penuh.
- Membocorkan alamat stack (`printf("%p", buf)`) menghancurkan ASLR;
  jangan log pointer internal ke output user.
- Flag raw tanpa wrapper tetap valid bila deskripsi menyatakannya;
  verifier membandingkan token inner secara case-insensitive.
- Solver reproduktif: `scripts/solve_126_binary_gauntlet_1.py`
  (butuh instance RUNNING; port via argv).
