# 748 ABSOLUTE NANO (picoCTF 2026, General Skills, Medium)

## Challenge Metadata
- ID: 748 | Nama: ABSOLUTE NANO | Event: picoCTF 2026
- Kategori: General Skills | Tingkat: Medium
- Flag: `academy{n4n0_411_7h3_w4y_81311b87}`
- Verifikasi: POST /api/submissions/ -> `{"correct": true}`

## Problem Statement & Scope
Lab SSH on-demand (`PUT /api/challenges/748/instance/`).
Deskripsi: "You have complete power with nano. Think you can get the flag?"
`sudo -l` menunjukkan `(ALL) NOPASSWD: /bin/nano /etc/sudoers`.
File flag `/home/ctf-player/flag.txt` milik root mode 440 (tak terbaca user).

## Teori & Akar Kerentanan (Root Cause)
Aturan sudo mengizinkan editor berjalan sebagai root demi administrasi
sudoers, tetapi biner editor adalah capability yang jauh lebih luas dari
satu file. nano yang berjalan sebagai root dapat MEMBACA file apa pun
melalui fitur Read File (^R). Ini varian klasik GTFOBins: pembatasan
argumen (`/etc/sudoers`) tidak membatasi kemampuan baca file internal
editor. Prinsip least privilege dilanggar: tugas "edit satu file"
diberi kapabilitas "baca semua file sebagai root".

## Rekonstruksi Pengujian Terstruktur
1. Luncurkan lab: `PUT /api/challenges/748/instance/` -> tunggu
   `status == RUNNING`, parse `ssh -p <port> ctf-player@<host>`.
2. Konfirmasi: `sudo -l` -> `(ALL) NOPASSWD: /bin/nano /etc/sudoers`.
3. Buka `sudo /bin/nano /etc/sudoers` lewat pty (TERM=xterm-256color).
4. Tekan ^R (Read File), paste path `/home/ctf-player/flag.txt` via
   bracketed paste, komit dengan CR (`\r`).
5. Flag ter-render di layar nano: `academy{n4n0_411_7h3_w4y_81311b87}`.
6. Submit: `POST /api/submissions/` -> `correct: true`.

## Flag & Verifikasi
- Flag: `academy{n4n0_411_7h3_w4y_81311b87}` (native, sudah format komunitas).
- Bukti: respons API `{"user": 1072359, "challenge": 748, "correct": true}`.

## Takeaway Kompetensi LKS & Mitigasi Defensif
- Jangan beri NOPASSWD pada editor interaktif; gunakan `sudoedit`
  (menyunting salinan user lalu memindahkan atomik sebagai root) atau
  wrapper skrip tervalidasi argumen.
- Harden sudoers: batasi `NOEXEC`, gunakan allowlist perintah non-interaktif.
- PTY quirk operasional: di prompt nano, komit dengan CR bukan LF;
  LF membuat renderer nano macet (layar kosong, koneksi hidup).
- Latihan LKS: identifikasi GTFOBins dari output `sudo -l` dalam <2 menit.
