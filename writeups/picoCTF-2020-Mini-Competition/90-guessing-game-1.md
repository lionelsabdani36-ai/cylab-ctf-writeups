# Guessing Game 1 (picoCTF 2020 Mini-Competition, Binary Exploitation, Challenge 90)

## Vulnerability

`win()` reads up to 360 bytes with `fgets` into a 112-byte stack buffer and
has **no stack protector** (`__stack_chk_fail` is never referenced from
`win`/`do_stuff`/`main`). Saved RBP sits at offset 112, saved RIP at
offset 120. Binary is static, non-PIE, so gadget addresses are fixed.

The guessing game itself needs no brute force: `get_random()` uses glibc
`rand()` without any `srand()` call, so the seed is the default (1) and the
first answer is always `rand()%100+1 = 84`. Verified locally against glibc
and against the challenge binary.

## Exploit (ret2syscall execve, two stages)

Gadgets (fixed addresses, no PIE):

| Gadget | Address |
|--------|---------|
| `pop rdi; ret` | 0x40206f |
| `pop rsi; ret` | 0x40a0de |
| `pop rdx; xor eax,eax; pop rbp; pop r12; ret` | 0x422b69 |
| `pop rax; ret` | 0x4518e7 |
| `syscall; ret` | 0x41b406 |
| `__read` | 0x450e80 |

Writable `.bss` at 0x4c9400.

Stage 1 (stack overflow in `win()`): `read(0, 0x4c9400, 0x200)`, then return
into 0x4c9400. Stage 2 (read via stdin into `.bss`): the string `/bin/sh`
followed by `execve(0x4c9400, NULL, NULL)` (`rdi=BSS, rsi=0, rdx=0, rax=59,
syscall`).

## Solver

`scripts/solve_90_guessing_game_1.py [host] [port]` — sends `84`, the ROP
stage 1, then the stage-2 blob, and prints the shell output (`cat flag*`).

Submitted via `POST /api/submissions/`.
