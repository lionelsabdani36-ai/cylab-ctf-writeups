# Writeup: ARMssembly 1 (Challenge ID: 111)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Assembly Analysis
- **Difficulty:** Easy (2)
- **Author:** Pranay Garg
- **Event:** picoCTF 2021
- **Points:** 70
- **Flag:** `academy{00000014}`

---

## Problem Statement & Scope
Diberikan `chall_1.S` (ARM assembly). Program mencetak `win` untuk argumen tertentu. Variabel: `a = 60, b = 0, c = 3`. Tugas: tentukan argumen pemenang; flag = representasi heksadesimal 32-bit (huruf kecil, tanpa `0x`).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Jejak Fungsi:** `func(arg)`: `tmp = (a << b)` = `60 << 0` = 60; `tmp = tmp // c` = `60 // 3` = 20; `tmp = tmp - arg` = `20 - arg`. `main` mencetak `win` iff `func(x) == 0`.
2. **Solusi Aljabar:** `20 - x = 0` → `x = 20` = `0x14`.
3. **Format Flag:** 32-bit hex lowercase tanpa prefix: `20` → `00000014`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh sumber:
   ```bash
   curl -sL -O https://challenge-files.cylabacademy.net/library/faf1dc0995a3edfb49290cb451b6c151521d8979a6b05fb4220e313b49a709a1/chall_1.S
   ```
2. Baca `func`: shift kiri, bagi integer, kurangi argumen.
3. Selesaikan `20 - x = 0` → `x = 20` → `academy{00000014}`.

---

## Flag & Verifikasi
- **Flag:** `academy{00000014}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201); GET `/api/challenges/111/` menunjukkan `solved_by_user: true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Baca Assembly Per Instruksi:** Lacak nilai register langkah-demi-langkah; soal Easy selalu linier tanpa cabang tersembunyi.
- **Format Output:** Perhatikan spesifikasi (32-bit, lowercase, tanpa `0x`) — jawaban benar dengan format salah tetap ditolak.
- **Mitigasi:** Perbandingan rahasia di sisi klien mudah dibalik; validasi lisensi/kunci harus di server.
