# Writeup: Serpentine (Challenge ID: 251)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Python Static Analysis
- **Difficulty:** Easy
- **Event:** Beginner picoMini 2022
- **Points:** 50
- **Flag:** `academy{7h3_r04d_l355_7r4v3l3d_825b10ae}`

---

## Problem Statement & Scope
Diberikan program Python interaktif `serpentine.py`. Program menyediakan opsi menu untuk mencetak pesan acak atau mencetak flag, namun fungsi pencetak flag tidak pernah dipanggil dalam aliran kontrol normal.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Client-Side Secret Embedding:** Program menyimpan byte terenkripsi dan kunci statis (`enkidu`) langsung di dalam kode sumber Python sisi klien.
2. **Kelemahan Kontrol Alur Eksekusi:** Aliran program sengaja dirancang untuk tidak mencapai cabang pencetak flag, namun algoritma dekripsi `str_xor` dapat dieksekusi secara independen.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis kode sumber `serpentine.py`.
2. Temukan fungsi `print_flag()` yang mendekripsi ciphertext flag menggunakan fungsi `str_xor(flag_enc, "enkidu")`.
3. Panggil langsung logika dekripsi tanpa melalui menu interaktif menggunakan script Python sederhana:
   ```python
   str_xor(flag_enc, "enkidu")
   ```
4. Output menghasilkan token flag valid.

---

## Flag & Verifikasi
- **Flag:** `academy{7h3_r04d_l355_7r4v3l3d_825b10ae}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pemisahan Kredensial:** Jangan pernah menanamkan rahasia atau kunci enkripsi pada kode yang didistribusikan ke klien.
- **Server-Side Validation:** Validasi otentikasi wajib dikelola di server backend terproteksi.
