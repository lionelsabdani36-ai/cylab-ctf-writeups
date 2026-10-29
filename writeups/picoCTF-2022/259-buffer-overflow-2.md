# buffer overflow 2 (Challenge 259, Binary Exploitation)

- **ID:** 259 | **Event:** picoCTF 2022 | **Kategori:** Binary Exploitation / ret2win + Arguments on Stack | **Level:** Medium
- **Flag:** `academy{argum3nt5_4_d4yZ_0f3d7e91}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
Binary ELF 32-bit: `vuln()` memanggil `gets()` ke `buf[100]`
(`lea -0x6c(%ebp)`, 108 byte di bawah `ebp`) lalu `puts()`.
Ada fungsi `win(0xCAFEF00D, 0xF00DF00D)` di `0x080491e6` yang mencetak
flag bila kedua argumen cocok (`cmpl $0xcafef00d,0x8(%ebp)` dan
`cmpl $0xf00df00d,0xc(%ebp)`). Lab on-demand `nc host port`.

## Root Cause
`gets()` tanpa batas menimpa saved `ebp`/`eip`; offset ret = 108
(buf) + 4 (saved ebp) = 112. Karena 32-bit cdecl, argumen `win`
diletakkan di stack setelah alamat return: payload =
`b"A"*112 + p32(win) + p32(ret-sled) + p32(0xCAFEF00D) +
p32(0xF00DF00D)`. Validasi hanya di dalam `win` — mencapai `win`
dengan argumen benar adalah seluruh exploit.

## Rekonstruksi
1. Unduh `vuln` + source dari CDN; konfirmasi alamat `win`
   (`readelf -s` → `080491e6`) dan offset buf (`lea -0x6c(%ebp)`,
   offset ret 112).
2. Start instance: `PUT /api/challenges/259/instance/` → catat
   `nc chatelaine.cylabacademy.net <port>`.
3. Kirim payload ret2win dua-argumen via socket.
   Otomasi: `python3 scripts/solve_259_buffer_overflow_2.py [h] [p]`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).
   Instance di-STOP setelah solve.

## Mitigasi
Ganti `gets()` dengan `fgets()`; kompilasi dengan stack canary,
NX, PIE+ASLR; pisahkan fungsi privileged dari binary yang
diekspos; fuzz dengan ASan sebelum rilis.

## Takeaway LKS
Klasifikasi Binary Exploitation: anatomi stack 32-bit (buf→ebp→ret),
konvensi cdecl (argumen di stack), dan ret2win multi-argumen.
Fondasi ROP: mengendalikan `eip` lalu menyiapkan stack seperti
panggilan fungsi normal.
