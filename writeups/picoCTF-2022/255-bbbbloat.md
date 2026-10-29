# Bbbbloat (Challenge 255, Reverse Engineering)

- **ID:** 255 | **Event:** picoCTF 2022 | **Kategori:** Reverse Engineering / Obfuscation | **Level:** Medium
- **Flag:** `academy{cu7_7h3_bl047_1cf3a481}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
Binary PIE x86-64 stripped meminta "What's my favorite number?".
Jawaban benar memicu decode string stack ter-obfuscate menjadi flag.

## Root Cause
Pemeriksaan membandingkan input dengan konstanta `0x86187`
(549255) yang terlihat di disassembly (`objdump` menemukan `$0x86187`
unik di atas 255). Blob terenkripsi disimpan sebagai 4 qword
little-endian (`0x4C4A3E3635323432`, `0x3062396630664634`,
`0x34603066635F3D33`, `0x4E606763326237`); tiap byte `c`
(`0x20 < c`, `c != 0x7f`) ditransformasi `c + 0x2f` dengan wrap di atas
`0x7e` kembali sebesar `0x5e`. Blob `24256>JL4Ff0f9b03=_cf0\`47b2cg\`N`
decode menjadi flag. Pure emulation — tanpa eksekusi (chmod+exec
diblokir di runner headless).

## Rekonstruksi
1. Unduh binary `bbbbloat` dari CDN challenge-files.
2. `objdump -d`: temukan konstanta `0x86187` (favorite number) dan 4
   qword blob terenkripsi.
3. Emulasikan transformasi byte di Python. Otomasi:
   `python3 scripts/solve_255_bbbbloat.py`.
4. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Jangan simpan secret ter-obfuscate reversibel di binary; validasi
di server, gunakan white-box crypto atau remote attestation bila
offline-check tak terhindarkan. Strip + obfuscation hanya menunda,
bukan mencegah, analisis statis.

## Takeaway LKS
Klasifikasi Reverse Engineering: membaca konstanta dari disassembly,
endianness qword blob, dan emulasi transformasi byte tanpa eksekusi
binary. Relevan defensif: mengapa client-side secret check rapuh.
