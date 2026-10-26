# Writeup: Collaborative Development (Challenge ID: 410)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Git Branch Management
- **Difficulty:** Easy
- **Author:** Jeffery John
- **Event:** picoCTF 2024
- **Points:** 75
- **Flag:** `academy{t3@mw0rk_m@k3s_th3_dr3@m_w0rk_f92d3827}`

---

## Problem Statement & Scope
Tim pengembang sedang mengerjakan fitur baru untuk aplikasi pencetak flag (`flag.py`) secara kolaboratif menggunakan percabangan Git (*feature branches*). Tantangan meminta penggabungan hasil kerja tim untuk merekonstruksi flag utuh.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Manajemen Cabang Git (Branching Workflow):** Cabang Git adalah pointer bergerak yang merujuk pada commit tertentu. Fitur-fitur modular yang dikembangkan secara terpisah disimpan di cabang independen (`feature/*`) sebelum digabungkan (*merge*) ke cabang utama (`main`/`master`).
2. **Fragmen Data Terisolasi:** Data sensitif yang dipecah dan disimpan di berbagai cabang dapat direkonstruksi oleh siapa pun yang memiliki akses baca ke repositori dengan menelusuri setiap cabang referensi.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Enumerasi seluruh cabang lokal dan remote:
   ```bash
   git branch -a
   # Output:
   # feature/part-1
   # feature/part-2
   # feature/part-3
   # * main
   ```
2. Periksa isi berkas `flag.py` pada masing-masing cabang fitur:
   ```bash
   git show feature/part-1:flag.py
   # print("academy{t3@mw0rk_", end='')

   git show feature/part-2:flag.py
   # print("m@k3s_th3_dr3@m_", end='')

   git show feature/part-3:flag.py
   # print("w0rk_f92d3827}")
   ```
3. Gabungkan ketiga potongan string berurutan:
   `academy{t3@mw0rk_` + `m@k3s_th3_dr3@m_` + `w0rk_f92d3827}` = `academy{t3@mw0rk_m@k3s_th3_dr3@m_w0rk_f92d3827}`.

---

## Flag & Verifikasi
- **Flag:** `academy{t3@mw0rk_m@k3s_th3_dr3@m_w0rk_f92d3827}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Prinsip Branch Protection & Access Control:** Pada lingkungan perusahaan, terapkan branch protection rules dan signed commits. Pastikan pengembang tidak meninggalkan cabang fitur usang (*stale branches*) yang memuat kode eksperimental atau kredensial uji coba.
- **Pembersihan Pasca-Merge:** Otomatisasi penghapusan cabang fitur setelah PR di-merge ke branch utama untuk meminimalkan attack surface inspeksi metadata.
