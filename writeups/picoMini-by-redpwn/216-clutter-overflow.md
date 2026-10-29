# clutter-overflow (Challenge 216, Binary Exploitation)

- **ID:** 216 | **Event:** picoMini by redpwn | **Kategori:** Binary Exploitation / Stack Buffer Overflow | **Level:** Medium
- **Flag:** `picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}` (terverifikasi live `POST /api/submissions/` -> `correct: true`; format `picoCTF{...}` asli)

## Skenario
`chall.c`: `char clutter[256]` diisi via `gets()`, lalu `code`
dibandingkan dengan `0xdeadbeef`; cocok → `system("cat flag.txt")`.
Lab statis `nc mars.cylabacademy.net 31890`.

## Root Cause
`gets()` tanpa batas menulis melewati buffer dan menimpa variabel
`code` di stack (layout: `clutter[rbp-0x110]`, `code[rbp-0x8]` →
offset 264). Validasi hanya membandingkan nilai, tanpa canary/ASLR
penuh — klasik stack smash satu tahap.

## Rekonstruksi
1. Unduh `chall.c` + `chall` dari CDN; konfirmasi offset di objdump
   (`lea rax,[rbp-0x110]` vs `cmp QWORD PTR [rbp-0x8]`).
2. Kirim `b"A"*264 + p64(0xdeadbeef) + b"\n"` via socket.
3. Server cocok → cetak flag. Otomasi:
   `python3 scripts/solve_216_clutter_overflow.py [host] [port]`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Ganti `gets()` dengan `fgets(buf, sizeof, stdin)`; aktifkan stack
canary (`-fstack-protector-strong`), PIE+ASLR, dan validasi panjang
input di semua baca buffer.

## Takeaway LKS
Klasifikasi Binary Exploitation: anatomi stack frame, offset
buffer→variabel, endianness payload. Fondasi ret2win: mengendalikan
aliran eksekusi lewat variabel sebelum mengendalikan RIP.
