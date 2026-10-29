# Writeup: unpackme.py (Challenge ID: 314)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Python + Fernet
- **Difficulty:** Easy
- **Event:** picoCTF 2022
- **Flag:** `academy{175_chr157m45_4d521283}`

---

## Problem Statement & Scope

File `unpackme.flag.py` (527 byte): token Fernet (`payload`) + kunci di dalam source (`key_str = 'correctstaplecorrectstaplecorrec'`, tepat 32 char → base64 → kunci Fernet valid). Inner script meminta password dan mencetak flag bila cocok.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kunci di dalam artefak:** `key_str` hard-coded di samping ciphertext — dekripsi statis selalu mungkin tanpa menjalankan payload.
2. **Fernet = AES128-CBC + HMAC:** aman sebagai primitif, tetapi model "kunci + ciphertext satu paket" setara plaintext bagi analis.
3. **`exec()` pada hasil dekripsi:** pola packer/loader Python; password check (`pw == 'batteryhorse'`) hanya gerbang UI, bukan proteksi kripto.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh `unpackme.flag.py` dari `challenge-files.cylabacademy.net`.
2. `python3 scripts/solve_314_unpackme_py.py unpackme.flag.py` → dekripsi Fernet statis → inner script → password `batteryhorse` → flag.
3. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

---

## Flag & Verifikasi

- **Flag:** `academy{175_chr157m45_4d521283}`
- **Bukti:** `solved_by_user=True` via `GET /api/challenges/314/`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Jangan pernah menyimpan kunci bersama ciphertext. Untuk proteksi nyata gunakan kunci terpisah (mis. turunan password via KDF + input pengguna) atau verifikasi lisensi server-side — bukan `if pw == ...` di kode yang didistribusikan.
