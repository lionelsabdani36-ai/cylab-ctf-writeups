# Writeup: 1_wanna_b3_a_r0ck5tar (Challenge ID: 82)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Esoteric Language
- **Difficulty:** Easy (2)
- **Author:** Alex Bushkin
- **Event:** picoCTF 2019
- **Points:** 350
- **Flag:** `academy{BONJOVI}`

---

## Problem Statement & Scope
Diberikan berkas lirik lagu (`r0ck5tar-lyrics.txt`). Petunjuk ("rockstar") mengarah ke bahasa pemrograman esoterik **Rockstar**, di mana kode sumber menyerupai lirik lagu. Tugas: jalankan "lagu" sebagai program dan baca keluarannya.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Rockstar Semantics:** Penugasan puitis (`X isagang ...` = poetic number dari jumlah huruf kata), pronoun `They` = variabel terakhir disebut, `Listen` = baca stdin numerik.
2. **Jebakan Transpiler:** Implementasi `rockstar-py` gagal pada sintaks lirik ini (`print(Tommy!)`, `They are`, `Break it down`, `Else` indent, perbandingan str-vs-int pada `Listen`) — eksekusi langsung menghasilkan output kosong.
3. **Emulasi Manual:** Evaluasi semantik baris-per-baris menghasilkan deret byte `[66,79,78,74,79,86,73]` = ASCII `BONJOVI`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh lirik:
   ```bash
   curl -sL -O https://challenge-files.cylabacademy.net/library/1961679e482fd1537dc967de3770d328b08c5821425e25289559a3d5029fc4ef/r0ck5tar-lyrics.txt
   ```
2. Coba transpiler `rockstar-py` — gagal beruntun: `SyntaxError` pada `print(Tommy!)`, `They are`, `Break outside loop`, `Else` indent, `EOFError` stdin, lalu output kosong karena `input()` str vs int.
3. Emulasi manual poetic numbers + pronoun + aritmetika Rockstar → `[66,79,78,74,79,86,73]`.
4. `bytes([66,79,78,74,79,86,73]).decode()` = `BONJOVI` → kemas `academy{BONJOVI}`.

---

## Flag & Verifikasi
- **Flag:** `academy{BONJOVI}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201); GET `/api/challenges/82/` menunjukkan `solved_by_user: true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Jangan Percaya Transpiler Buta:** Esolang punya banyak dialek — saat tool gagal, emulasi semantik manual per baris justru lebih cepat.
- **Poetic Numbers:** Kuasai aturan literal puitis Rockstar (jumlah huruf kata, titik desimal) — pola favorit pembuat soal.
- **Mitigasi:** Ofuskasi via esolang bukan keamanan; logika sensitif tetap di server, bukan di artefak yang dibagikan.
