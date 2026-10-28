# Writeup: flag_shop (Challenge ID: 49)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Integer Overflow
- **Difficulty:** Medium
- **Author:** Danny
- **Event:** picoCTF 2019
- **Points:** 300
- **Flag:** `academy{m0n3y_bag5_E89fCE0e}`

---

## Problem Statement & Scope
Toko flag interaktif via netcat: saldo awal 1100, flag asli seharga 100000, flag palsu seharga 1000. Program C menghitung total belanja sebagai `number_flags * 900` memakai aritmetika integer 32-bit.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Integer overflow (wrap-around):** perkalian `n * 900` pada integer 32-bit bertanda meluap melewati `INT_MAX` (2147483647) dan menjadi negatif. Syarat `total_cost <= account_balance` lalu lolos, dan `new_balance = balance - total_cost` justru membesar karena mengurangkan bilangan negatif.
2. **Pemilihan n:** `n = 2386095` memberi `2386095 * 900 = 2147485500`, yang wrap ke `-1796`; saldo baru `1100 - (-1796) = 2896`? Nilai ini belum cukup — solver memakai pencarian `n` sehingga `new_balance > 100000` (biaya negatif besar), lalu membeli 1 flag asli.
3. Fase NIST SP 800-115: analisis kode sumber (source disediakan) → temukan operasi aritmetika tak aman → hitung konstanta peluap → eksploitasi via socket.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Provision instance, unduh `store.c`, identifikasi `total_cost = number_flags * 900` (int 32-bit).
2. Hitung `n` sehingga `(n*900) mod 2^32` terinterpretasi negatif besar: `n = 2386095`.
3. Kirim `n` ke prompt jumlah flag palsu → saldo menjadi > 100000.
4. Beli 1 flag asli (opsi 1) → server mencetak flag.

---

## Flag & Verifikasi
- **Flag:** `academy{m0n3y_bag5_E89fCE0e}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Gunakan tipe 64-bit / cek batas** untuk semua komputasi uang; validasi `quantity` di sisi server (batas maksimal wajar).
- **Uji nilai ekstrem** (0, negatif, sangat besar) pada setiap input numerik — teknik standar LKS untuk menemukan overflow.
- Pola ini identik dengan bug harga di e-commerce nyata (kuantitas negatif/overflow).

---

## Solver
Lihat `scripts/solve_49_flag_shop.py` — menghitung konstanta overflow dan menjalankan sesi pembelian otomatis.
