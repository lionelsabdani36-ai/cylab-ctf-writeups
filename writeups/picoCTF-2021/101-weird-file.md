# Writeup: Weird File (Challenge ID: 101)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Malicious Macro Document
- **Difficulty:** Easy
- **Author:** thelshell
- **Event:** picoCTF 2021
- **Points:** 20
- **Flag:** `academy{m4cr0s_r_d4ng3r0us}`

---

## Problem Statement & Scope
Disediakan `weird.docm` (dokumen Word berkemampuan makro) dengan deskripsi "what could go wrong if we let Word documents run programs?" dan petunjuk video YouTube tentang makro berbahaya.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Makro VBA Berbahaya:** Format `.docm` mengizinkan kode VBA tereksekusi; penyerang menyematkan payload yang dijalankan saat dokumen dibuka (atau via `AutoOpen`/`Document_Open`).
2. **Analisis Statis Aman:** Jangan buka dokumen di Word — ekstrak aliran OLE (`oletools`/`olevba`), periksa modul VBA, string mencurigakan, dan perintah shell/powershell.
3. **Rekayasa Sosial:** Dokumen berbahaya sering menyuruh korban "Enable Content"; flag latihan ini mengedukasi agar tidak pernah melakukannya.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh `weird.docm`.
2. Ekstrak aliran makro tanpa mengeksekusi (mis. `olevba weird.docm` atau unzip + inspeksi `word/vbaProject.bin`).
3. Baca sumber VBA yang terobfusikasi ringan; temukan string flag.
4. Flag: `academy{m4cr0s_r_d4ng3r0us}`.

---

## Flag & Verifikasi
- **Flag:** `academy{m4cr0s_r_d4ng3r0us}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Blokir Makro via GPO:** Nonaktifkan makro Office dari internet (Mark-of-the-Web) di seluruh organisasi.
- **Sandbox & Detonasi:** Buka lampiran mencurigakan di sandbox terisolasi dengan AV/EDR modern.
- **Edukasi Phishing:** Latih pengguna mengenali umpan "Enable Content".

---

## Solver
Lihat `scripts/solve_101_weird_file.py` — mengekstrak string flag dari aliran VBA tanpa mengeksekusi dokumen.
