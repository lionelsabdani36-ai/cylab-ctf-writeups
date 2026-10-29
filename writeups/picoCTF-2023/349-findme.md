# Writeup: findme (Challenge ID: 349)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Redirect Chains
- **Difficulty:** Easy
- **Event:** picoCTF 2023
- **Flag:** `academy{proxies_all_the_way_661fc398}`

---

## Problem Statement & Scope

Form login Express (`action=/login`). Login `test` / `test!` → 302 ke `/next-page/id=<b64#1>` → halaman JS-redirect ke `/next-page/id=<b64#2>` → `/home` (bank demo, decoy). Hint: "any redirections?".

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Flag dipecah عبر rantai redirect:** segmen 1 (`academy{proxies_al`) di `Location` header 302; segmen 2 (`l_the_way_661fc398}`) di `window.location` halaman berikut. Klien otomatis mengikuti redirect tanpa membaca isinya → analis manual/curl menang.
2. **JS-redirect sebagai gerbang:** `setTimeout(() => window.location = ...)` — cukup `curl` tanpa eksekusi JS + regex `/next-page/id=...`.
3. **Base64 bukan enkripsi:** decode tiap segmen → konkatenasi = flag utuh.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Launch: `PUT /api/challenges/349/instance/` → catat base URL.
2. `python3 scripts/solve_349_findme.py <base-url>` (POST /login tanpa follow-redirect, ekstrak `id=` dari `Location`, GET berantai, base64-decode tiap segmen).
3. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

---

## Flag & Verifikasi

- **Flag:** `academy{proxies_all_the_way_661fc398}`
- **Bukti:** `solved_by_user=True` via `GET /api/challenges/349/`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Selalu inspek `Location` header dan body perantara rantai redirect (curl `-D -` tanpa `-L` dulu). Defensif: jangan letakkan data sensitif di URL — URL tercatat di log proxy/browser history.
