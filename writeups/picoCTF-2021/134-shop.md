# Writeup: Shop (Challenge ID: 134)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Logic Flaw
- **Difficulty:** Medium
- **Author:** picoCTF
- **Event:** picoCTF 2021
- **Points:** 90
- **Flag:** `academy{b4d_brogrammer_0ca0fc368}`

---

## Problem Statement & Scope
Toko interaktif (binary Go 32-bit, `source`) via `nc xebec.cylabacademy.net 28686`.
Modal 40 koin; daftar: Quiet Quiches (10), Average Apple (15), Fruitful Flag
(100, stok 1). Menu: beli item, jual item, exit. Target: beli flag tanpa 100 koin.

---

## Teori & Akar Kerentanan (Root Cause Theory)
Path pembelian menghitung `total = price * qty` lalu `coins -= total` tanpa
validasi `qty > 0` (missing input validation / CWE-20, integer logic flaw).
Jumlah negatif membalik tanda: `coins -= 10 * (-10)` sama dengan `coins += 100`,
sekaligus menambah stok (`count -= qty`). Ini kerentanan logika bisnis, bukan
memory corruption — biner tidak perlu dibedah lebih jauh setelah string
`"You have %d coins"` dan `"How many do you want to buy?"` terkonfirmasi.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh `source` dari link deskripsi instance; `file` menunjuk ELF Go 32-bit.
2. Hubungkan via socket Python (`nc` tidak tersedia di worker): banner
   menunjukkan 40 koin dan menu 0-4.
3. Kirim `0` lalu `-5`: saldo naik 40 -> 90 (validasi hipotesis negatif).
4. Kirim `0` + `-10` dua kali: saldo 40 -> 140 -> 240.
5. Kirim `2` lalu `1`: beli Fruitful Flag seharga 100 koin.
6. Server menjawab `Flag is: [97 99 97 ...]` — array byte desimal.
7. Decode byte array ke ASCII: `academy{b4d_brogrammer_0ca0fc368}`.

---

## Flag & Verifikasi
- **Flag:** `academy{b4d_brogrammer_0ca0fc368}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan
  `{"challenge": 134, "correct": true}` (HTTP 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Validasi sisi server:** tolak `qty <= 0` dan verifikasi `coins >= price*qty`
  sebelum mutasi state; uji edge case negatif/nol/overflow pada tiap input numerik.
- **Uji batas (boundary testing):** hint "Always check edge cases" menunjuk
  langsung ke kelas uji LKS — sertakan kasus negatif dalam test plan.
- **Defensive:** log transaksi dan kunci stok agar tidak bisa digelembungkan
  via pembelian negatif.
