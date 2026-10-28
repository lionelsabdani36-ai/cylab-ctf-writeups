# Writeup: Guessing Game 1 (Challenge ID: 90)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / ret2syscall ROP
- **Difficulty:** Easy
- **Event:** picoCTF 2020 Mini-Competition
- **Points:** 200
- **Flag:** `academy{r0p_y0u_l1k3_4_hurr1c4n3_3ea9d94813b570b2}`

---

## Problem Statement & Scope
Game tebak angka via netcat. Jawaban `rand() % 100 + 1` tanpa `srand()`
(sead default → jawaban pertama selalu **84**). Menang memanggil `win()` yang
`fgets(winner, 360, stdin)` ke frame stack `0x70` byte tanpa stack protector
— overflow klasik menuju kontrol RIP. Biner statik non-PIE: alamat gadget
tetap, `.bss` writable di `0x4c9360`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **PRNG tanpa seed:** glibc `rand()` tanpa `srand()` deterministik
   (seed 1) → tidak perlu brute force, jawab `84`.
2. **Stack buffer overflow:** `fgets(360)` ke buffer frame `0x70` menimpa
   saved RBP (offset 112) dan RIP (offset **120**, terverifikasi live).
3. **ret2syscall dua tahap:** tanpa `system()` di biner, pakai gadget
   `read` untuk mendaratkan `/bin/sh` + rantai `execve` di `.bss`,
   lalu `ret` ke sana (bypass kebutuhan alamat stack/ASLR).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Provision instance (`PUT .../instance/` → 204, poll → `RUNNING`,
   `nc chatelaine.cylabacademy.net <port>`).
2. Kirim `84` → `win()` → prompt `Name?`.
3. Stage 1 (120 padding + ROP): `read(0, BSS=0x4c9460, 0x180)`, lalu
   `ret BSS`. Gadget (objdump-terverifikasi):
   `pop rdi` 0x40206f · `pop rsi;pop r15` 0x40206d ·
   `pop rax;pop rdx;pop rbx` 0x486bba (aligned) ·
   `pop rdx;xor eax,eax;pop rbp;pop r12` 0x422b69 ·
   `syscall` 0x41b406 · `read` 0x450e80.
4. Stage 2 (via read ke BSS): `/bin/sh\x00` +
   `execve(BSS, NULL, NULL)` (`rdi=BSS, rsi=0, rdx=0, rax=59, syscall`).
5. `id; cat flag*` → `academy{r0p_y0u_l1k3_4_hurr1c4n3_3ea9d94813b570b2}`.
6. Submit via API → `{"correct": true}` (HTTP 201).

---

## Flag & Verifikasi
- **Flag:** `academy{r0p_y0u_l1k3_4_hurr1c4n3_3ea9d94813b570b2}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}`
  (HTTP 201); `solved_by_user: true` pada `GET /api/challenges/90/`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Seed PRNG dari entropi aman** (`getrandom`/`srand(time^pid)`); jangan
  andalkan `rand()` default untuk logika game/undian.
- **Batasi baca input** (`fgets(buf, sizeof(buf), ...)`) + aktifkan
  stack protector (`-fstack-protector-strong`), NX + PIE + ASLR penuh.
- Teknik `read-then-ret-to-.bss` adalah pola wajib LKS untuk biner statik
  tanpa `system()` — kuasai rantai `pop r*/syscall`.

---

## Solver
Lihat `scripts/solve_90_guessing_game_1.py [host] [port]` — kirim `84`,
stage-1 ROP `read`, stage-2 `execve`, cetak output shell.
