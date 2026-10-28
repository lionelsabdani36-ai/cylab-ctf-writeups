# Writeup: Stonks (Challenge ID: 105)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Format String
- **Difficulty:** Medium
- **Author:** madStacks
- **Event:** picoCTF 2021
- **Points:** 300
- **Flag:** `academy{I_l05t_4ll_my_m0n3y_9f0ca844}`

---

## Problem Statement & Scope
Aplikasi trading "stonks" via netcat membaca file `api` (berisi flag) ke buffer, lalu mencetak input pengguna dengan `printf(user_buf)` tanpa format — format-string leak klasik.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Format-string vulnerability:** `printf(token)` menafsirkan `%p`/`%x` pada input sebagai penentu baca stack; penyerang membaca memori proses termasuk buffer flag.
2. **Rekonstruksi little-endian:** tiap word tercetak (mis. `0x64616361`) adalah 4 byte ASCII terbalik (`61 63 61 64` = "acad"); gabungkan word-word ASCII berurutan untuk membaca flag.
3. Alur menu: pilih `1` (buy stonks) agar program sampai ke prompt `API token?`, lalu kirim muatan format.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Provision instance, hubungkan socket, kirim `1`.
2. Pada prompt token kirim `%p.` × 60, baca seluruh output.
3. Identifikasi word-word ASCII berurutan: `64616361 7b796d65 306c5f49 345f7435 6d5f6c6c 306d5f79 5f79336e 63306639 34343861 0a7d`.
4. Decode tiap word little-endian → `academy{I_l05t_4ll_my_m0n3y_9f0ca844}`.
5. Submit via API → `correct: true`.

---

## Flag & Verifikasi
- **Flag:** `academy{I_l05t_4ll_my_m0n3y_9f0ca844}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Selalu gunakan format statis:** `printf("%s", buf)` — jangan pernah meneruskan input pengguna sebagai string format.
- **Teknik baca word terbalik** (`bytes.fromhex(w)[::-1]`) adalah pola wajib LKS untuk semua leak format-string/hexdump.
- Compiler flag `-Wformat-security` menangkap pola ini saat build.

---

## Solver
Lihat `scripts/solve_105_stonks.py` (sudah ada di repo) — leak `%p`, rangkai word ASCII, cetak flag.
