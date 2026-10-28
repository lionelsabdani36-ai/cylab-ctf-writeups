# Stonks (picoCTF 2021, Binary Exploitation, Challenge 105)

## Vulnerability

Classic format-string bug in `buy_stonks()`: the program reads the flag file
`api` into a heap buffer, then prints attacker input with a bare
`printf(user_buf)`. Any `%x`/`%llx` specifiers in the API-token prompt leak
stack/heap words — including the flag bytes.

## Exploit

1. Choose menu option `1` (buy stonks).
2. At the `API token?` prompt, send many `%llx` specifiers (e.g. 60).
3. The response echoes hex words; the flag appears as consecutive ASCII-range
   words. Reverse each word's byte order (little-endian) and concatenate:
   `bytes.fromhex(word)[::-1]` for each printable word spells
   `academy{...}` (original picoCTF flag was
   `picoCTF{I_l05t_4ll_my_m0n3y_...}`).

## Solver

`scripts/solve_105_stonks.py <host> <port>` — leaks and auto-decodes.

Submitted via `POST /api/submissions/`.
