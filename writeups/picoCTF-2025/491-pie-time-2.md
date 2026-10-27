# Writeup: PIE TIME 2 (Challenge ID: 491)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Format String Leak & PIE Bypass
- **Difficulty:** Medium
- **Event:** picoCTF 2025
- **Points:** 200
- **Flag:** `academy{p13_5h0u1dn'7_134k_13db9a90}`

---

## Problem Statement & Scope
Pengembangan dari PIE TIME, kali ini biner tidak lagi membocorkan alamat `main` secara otomatis. Peserta harus menemukan cara membocorkan alamat biner sendiri untuk mengarahkan eksekusi ke `win()`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Format String Vulnerability:** Program memanggil `printf(user_buffer)` tanpa format specifier, memungkinkan penyerang membaca data dari stack memori melalui positional format token `%N$p`.
2. **Stack Return Address Leak:** Return address pada stack frame mengarah ke biner, sehingga basis PIE dapat dihitung.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Kirim format payload `%19$p` untuk membaca return address `main+0x44` dari stack.
2. Hitung alamat fungsi `win()` menggunakan offset relatif:
   $$	ext{win} = 	ext{leak} - 0xe6$$
3. Masukkan alamat `win` pada prompt jump address untuk memicu rutin pencetak flag.

---

## Flag & Verifikasi
- **Flag:** `academy{p13_5h0u1dn'7_134k_13db9a90}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Strict Format String Practice:** Selalu gunakan format string statis (`printf("%s", input)`).
